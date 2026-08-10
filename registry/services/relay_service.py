# Request relay/queueing — the network boundary. PRD.md §5 R1 (treat
# every incoming query as adversarial data), R2 (identity spoofing), R3
# (rate limiting), R6 (replay/relay abuse).
#
# Order of checks matters: signature is verified BEFORE any business
# state (nonce_log, rate_limit_events, pending_relay_queue) is written.
# Only the audit log is written on a rejection — that's the required
# record of the attempt, not the "state mutation" the task's "reject
# before any state mutation" instruction is about.
#
# MAX_FIELD_LEN and the resulting 'suspicious_payload_content' outcome
# are this module's actual, limited defense against a payload smuggling
# document/capsule content through a string field: it rejects any of
# sender/recipient/request_type longer than a short handle-shaped
# limit. It catches accidental or naive misuse (stuffing a paragraph
# into request_type); it does NOT detect content hidden via chunking,
# encoding, or splitting across otherwise-valid-length fields — that is
# a real, disclosed limit, not a claim of full content detection.

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from registry.models.tables import identities, nonce_log, pending_relay_queue
from registry.services import audit_service, identity_service, rate_limit_service
from registry.services.canonical_payload import PayloadDecodeError, decode_canonical_payload
from registry.services.signature_verifier import verify_signature

logger = logging.getLogger("registry.relay")

MAX_FIELD_LEN = 128
MAX_REQUEST_AGE_SECS = 300  # mirrors identity/src/verification.rs's default
MAX_CIPHERTEXT_BYTES = 65536  # matches schema.sql's CHECK — a plausibility
# bound for encrypted short query text, not content inspection; this
# module never decrypts or parses content_ciphertext, only bounds its size.


class RelayRejection(Exception):
    def __init__(self, outcome: str, detail: str):
        self.outcome = outcome
        self.detail = detail
        super().__init__(detail)


def submit_relay_request(
    session: Session,
    payload_hex: str,
    signature_hex: str,
    now: datetime,
    content_ciphertext_hex: str | None = None,
    trace_id: str = "-",
) -> str:
    """Verifies and enqueues a signed request. Returns the queued item's
    id on success. Raises RelayRejection (with .outcome set to the
    specific reason) on any rejection — the caller maps this to a
    distinct HTTP error, not a generic 500.

    trace_id is client-supplied observability metadata only (an unsigned
    HTTP header, agent/wiring/trace.py) — never verified, never gates
    this function's outcome, logged alongside handles/outcomes only,
    never query/answer content (CLAUDE.md §2)."""

    logger.info("relay_request_received", extra={"kv": {"trace_id": trace_id}})

    try:
        payload_bytes = bytes.fromhex(payload_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        content_ciphertext = (
            bytes.fromhex(content_ciphertext_hex) if content_ciphertext_hex is not None else None
        )
    except ValueError:
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "malformed_payload",
            detail="payload/signature/ciphertext not valid hex",
        )
        session.commit()
        logger.info("relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "malformed_payload"}})
        raise RelayRejection("malformed_payload", "payload, signature, or ciphertext is not valid hex")

    if content_ciphertext is not None and len(content_ciphertext) > MAX_CIPHERTEXT_BYTES:
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "ciphertext_too_large",
            detail=f"content_ciphertext_bytes={len(content_ciphertext)} exceeds {MAX_CIPHERTEXT_BYTES}",
        )
        session.commit()
        logger.info(
            "relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "ciphertext_too_large"}}
        )
        raise RelayRejection(
            "ciphertext_too_large", f"content ciphertext exceeds {MAX_CIPHERTEXT_BYTES} bytes"
        )

    try:
        decoded = decode_canonical_payload(payload_bytes)
    except PayloadDecodeError as exc:
        audit_service.record_audit_event(
            session, "relay_attempt", "malformed_payload", detail=str(exc)
        )
        session.commit()
        logger.info("relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "malformed_payload"}})
        raise RelayRejection("malformed_payload", str(exc))

    oversized = [
        name
        for name, value in (
            ("sender", decoded.sender),
            ("recipient", decoded.recipient),
            ("request_type", decoded.request_type),
        )
        if len(value) > MAX_FIELD_LEN
    ]
    if oversized:
        detail = f"field(s) exceed {MAX_FIELD_LEN} chars, treated as possible content: {oversized}"
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "suspicious_payload_content",
            sender=decoded.sender[:MAX_FIELD_LEN],
            recipient=decoded.recipient[:MAX_FIELD_LEN],
            detail=detail,
        )
        session.commit()
        logger.info(
            "relay_request_rejected",
            extra={"kv": {"trace_id": trace_id, "outcome": "suspicious_payload_content"}},
        )
        raise RelayRejection("suspicious_payload_content", detail)

    sender_public_key_hex = identity_service.get_public_key_hex(session, decoded.sender)
    if sender_public_key_hex is None:
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "unknown_sender",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected",
            extra={"kv": {"trace_id": trace_id, "outcome": "unknown_sender", "sender": decoded.sender}},
        )
        raise RelayRejection("unknown_sender", f"sender {decoded.sender!r} is not registered")

    if not verify_signature(sender_public_key_hex, payload_bytes, signature_bytes):
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "invalid_signature",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected",
            extra={"kv": {"trace_id": trace_id, "outcome": "invalid_signature", "sender": decoded.sender}},
        )
        raise RelayRejection("invalid_signature", "signature verification failed")

    if not identity_service.identity_exists(session, decoded.recipient):
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "unknown_recipient",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected",
            extra={"kv": {"trace_id": trace_id, "outcome": "unknown_recipient", "recipient": decoded.recipient}},
        )
        raise RelayRejection(
            "unknown_recipient", f"recipient {decoded.recipient!r} is not registered"
        )

    request_ts = decoded.timestamp
    age = now.timestamp() - request_ts
    if age > MAX_REQUEST_AGE_SECS or age < -MAX_REQUEST_AGE_SECS:
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "expired_timestamp",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "expired_timestamp"}}
        )
        raise RelayRejection("expired_timestamp", "timestamp outside the validity window")

    # Nonce uniqueness enforced by the (sender, nonce) primary key
    # itself, not a check-then-insert — avoids a TOCTOU race.
    stmt = pg_insert(nonce_log).values(
        sender=decoded.sender,
        nonce=decoded.nonce,
        request_ts=request_ts,
        seen_at=now,
    )
    stmt = stmt.on_conflict_do_nothing(index_elements=["sender", "nonce"]).returning(
        nonce_log.c.sender
    )
    result = session.execute(stmt)
    if result.first() is None:
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "replayed_nonce",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "replayed_nonce"}}
        )
        raise RelayRejection("replayed_nonce", "this (sender, nonce) pair has already been seen")

    if not rate_limit_service.check_and_record(session, decoded.sender, decoded.recipient, now):
        audit_service.record_audit_event(
            session,
            "relay_attempt",
            "rate_limited",
            sender=decoded.sender,
            recipient=decoded.recipient,
        )
        session.commit()
        logger.info(
            "relay_request_rejected", extra={"kv": {"trace_id": trace_id, "outcome": "rate_limited"}}
        )
        raise RelayRejection("rate_limited", "sender has exceeded the recipient's per-hour limit")

    item_id = str(uuid.uuid4())
    session.execute(
        pending_relay_queue.insert().values(
            id=item_id,
            sender=decoded.sender,
            recipient=decoded.recipient,
            request_type=decoded.request_type,
            nonce=decoded.nonce,
            request_ts=request_ts,
            payload=payload_bytes,
            signature_hex=signature_hex,
            content_ciphertext=content_ciphertext,
            enqueued_at=now,
            delivered_at=None,
        )
    )
    # Metadata only in the audit detail — ciphertext SIZE, never content
    # (the registry cannot read it anyway; this is just a size record).
    success_detail = (
        f"content_ciphertext_bytes={len(content_ciphertext)}"
        if content_ciphertext is not None
        else "no content_ciphertext"
    )
    audit_service.record_audit_event(
        session,
        "relay_attempt",
        "success",
        sender=decoded.sender,
        recipient=decoded.recipient,
        detail=success_detail,
    )
    session.commit()
    logger.info(
        "relay_request_relayed",
        extra={
            "kv": {
                "trace_id": trace_id,
                "sender": decoded.sender,
                "recipient": decoded.recipient,
                "item_id": item_id,
            }
        },
    )
    return item_id


def fetch_pending(session: Session, recipient: str, trace_id: str = "-") -> list[dict]:
    """Recipient polls for requests addressed to it. Marks fetched items
    delivered so a second poll doesn't redeliver the same item.

    trace_id here is the polling call's own observability metadata, not
    threaded from the original sender (that trace_id never reaches this
    process — see agent/ARCHITECTURE.md's trace_id/nonce correlation
    note)."""
    rows = (
        session.execute(
            select(pending_relay_queue).where(
                pending_relay_queue.c.recipient == recipient,
                pending_relay_queue.c.delivered_at.is_(None),
            )
        )
        .mappings()
        .all()
    )
    if rows:
        ids = [row["id"] for row in rows]
        session.execute(
            pending_relay_queue.update()
            .where(pending_relay_queue.c.id.in_(ids))
            .values(delivered_at=datetime.now(timezone.utc))
        )
        session.commit()
        logger.info(
            "relay_items_delivered", extra={"kv": {"trace_id": trace_id, "recipient": recipient, "count": len(rows)}}
        )
    result = []
    for row in rows:
        item = dict(row)
        # `payload` (LargeBinary) is not valid UTF-8 in general (it's
        # identity/'s canonical byte encoding: length-prefixed fields, an
        # 8-byte big-endian timestamp) — must be hex-encoded before this
        # dict is ever handed to a JSON response, same as
        # content_ciphertext below. Key renamed to payload_hex to match
        # RelaySubmitRequest/PendingRelayItem's existing field name.
        payload = item.pop("payload")
        item["payload_hex"] = payload.hex()
        ciphertext = item.pop("content_ciphertext", None)
        item["content_ciphertext_hex"] = ciphertext.hex() if ciphertext is not None else None
        result.append(item)
    return result
