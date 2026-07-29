# Grant storage (CRUD). PRD.md §4.2 "Consent-scoped memory" / §6 Grant.
#
# This is storage only. Revocation here just sets `revoked_at` —
# immediately, correctly, queryable. The actual enforcement (checking
# grant validity at capsule-load time, so an in-flight request fails
# under a grant revoked mid-request) is agent/resolver/'s job, not the
# registry's — this module does not reimplement that check-at-load-time
# logic (PRD.md §3.1 step 8). See registry/ARCHITECTURE.md.
#
# create_grant_signed/revoke_grant_signed below verify a signature
# BEFORE any grant state mutation — added because the original
# create_grant/revoke_grant took grantor/grant_id as unauthenticated
# claims, directly contradicting PRD.md §5 R2 ("MUST NEVER resolve
# grants or approvals based on a claimed handle string alone"). Mirrors
# relay_service.submit_relay_request's verify-before-mutate order and
# reuses its exact building blocks (signature_verifier, nonce_log,
# audit_service) rather than a fourth crypto pathway.

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from registry.models.tables import grants, nonce_log
from registry.services import audit_service, identity_service
from registry.services.grant_payload import (
    encode_grant_create_payload,
    encode_grant_revoke_payload,
    is_nonce_well_formed,
)
from registry.services.signature_verifier import verify_signature

MAX_REQUEST_AGE_SECS = 300  # mirrors relay_service's / identity's default


class GrantRejection(Exception):
    def __init__(self, outcome: str, detail: str):
        self.outcome = outcome
        self.detail = detail
        super().__init__(detail)


def _check_timestamp_and_nonce(
    session: Session, sender: str, timestamp: int, nonce: str, now: datetime
) -> None:
    if not is_nonce_well_formed(nonce):
        raise GrantRejection("malformed_payload", "nonce is missing or not 32 hex characters")

    age = now.timestamp() - timestamp
    if age > MAX_REQUEST_AGE_SECS or age < -MAX_REQUEST_AGE_SECS:
        raise GrantRejection("expired_timestamp", "timestamp outside the validity window")

    stmt = pg_insert(nonce_log).values(
        sender=sender, nonce=nonce, request_ts=timestamp, seen_at=now
    )
    stmt = stmt.on_conflict_do_nothing(index_elements=["sender", "nonce"]).returning(
        nonce_log.c.sender
    )
    if session.execute(stmt).first() is None:
        raise GrantRejection("replayed_nonce", "this (sender, nonce) pair has already been seen")


def create_grant_signed(
    session: Session,
    grantor: str,
    grantee: str,
    grant_type: str,
    scope_capsule_ids: list[str],
    expires_at: datetime | None,
    timestamp: int,
    nonce: str,
    signature_hex: str,
    now: datetime,
) -> str:
    """Verifies grantor's signature over every field being stored before
    creating the grant. Raises GrantRejection (caller maps .outcome to an
    HTTP status, same pattern as relay_service.RelayRejection)."""
    public_key_hex = identity_service.get_public_key_hex(session, grantor)
    if public_key_hex is None:
        audit_service.record_audit_event(
            session, "grant_create_attempt", "unknown_grantor", sender=grantor, recipient=grantee
        )
        session.commit()
        raise GrantRejection("unknown_sender", f"grantor {grantor!r} is not registered")

    expires_at_ts = int(expires_at.timestamp()) if expires_at is not None else None
    canonical_bytes = encode_grant_create_payload(
        grantor, grantee, grant_type, scope_capsule_ids, expires_at_ts, timestamp, nonce
    )
    if not verify_signature(public_key_hex, canonical_bytes, bytes.fromhex(signature_hex)):
        audit_service.record_audit_event(
            session, "grant_create_attempt", "invalid_signature", sender=grantor, recipient=grantee
        )
        session.commit()
        raise GrantRejection("invalid_signature", "signature verification failed")

    try:
        _check_timestamp_and_nonce(session, grantor, timestamp, nonce, now)
    except GrantRejection as rejection:
        audit_service.record_audit_event(
            session, "grant_create_attempt", rejection.outcome, sender=grantor, recipient=grantee
        )
        session.commit()
        raise

    grant_id = create_grant(session, grantor, grantee, grant_type, scope_capsule_ids, expires_at)
    audit_service.record_audit_event(
        session, "grant_create_attempt", "success", sender=grantor, recipient=grantee
    )
    return grant_id


def revoke_grant_signed(
    session: Session,
    grant_id: str,
    timestamp: int,
    nonce: str,
    signature_hex: str,
    now: datetime,
) -> None:
    """Looks up the grant's ACTUAL stored grantor and verifies against
    that identity — a request cannot claim a different grantor than the
    one who really owns the grant being revoked."""
    row = get_grant(session, grant_id)
    if row is None:
        raise GrantRejection("not_found", f"grant {grant_id!r} does not exist")
    grantor = row["grantor"]

    public_key_hex = identity_service.get_public_key_hex(session, grantor)
    if public_key_hex is None:
        raise GrantRejection("unknown_sender", f"grantor {grantor!r} is not registered")

    canonical_bytes = encode_grant_revoke_payload(grant_id, timestamp, nonce)
    if not verify_signature(public_key_hex, canonical_bytes, bytes.fromhex(signature_hex)):
        audit_service.record_audit_event(
            session, "grant_revoke_attempt", "invalid_signature", sender=grantor
        )
        session.commit()
        raise GrantRejection("invalid_signature", "signature verification failed")

    try:
        _check_timestamp_and_nonce(session, grantor, timestamp, nonce, now)
    except GrantRejection as rejection:
        audit_service.record_audit_event(
            session, "grant_revoke_attempt", rejection.outcome, sender=grantor
        )
        session.commit()
        raise

    revoke_grant(session, grant_id)
    audit_service.record_audit_event(session, "grant_revoke_attempt", "success", sender=grantor)


def create_grant(
    session: Session,
    grantor: str,
    grantee: str,
    grant_type: str,
    scope_capsule_ids: list[str],
    expires_at: datetime | None = None,
) -> str:
    grant_id = str(uuid.uuid4())
    session.execute(
        grants.insert().values(
            id=grant_id,
            grantor=grantor,
            grantee=grantee,
            grant_type=grant_type,
            scope_capsule_ids=scope_capsule_ids,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            revoked_at=None,
        )
    )
    return grant_id


def revoke_grant(session: Session, grant_id: str) -> None:
    session.execute(
        update(grants)
        .where(grants.c.id == grant_id)
        .values(revoked_at=datetime.now(timezone.utc))
    )


def get_grant(session: Session, grant_id: str):
    return session.execute(select(grants).where(grants.c.id == grant_id)).mappings().first()


def list_grants_for_grantee(session: Session, grantee: str):
    return (
        session.execute(select(grants).where(grants.c.grantee == grantee))
        .mappings()
        .all()
    )
