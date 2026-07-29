# Approval request lifecycle. PRD.md §6 Approval Request; §3.2 Ad Hoc
# Approval Flow. Default expiry 5h, approver-configurable.
#
# Expiry approach chosen: ON-READ CHECK, not a background/scheduled
# job. Justification: no scheduler/cron infra has been decided for
# this project (no Redis, no message queue — CLAUDE.md §4), so adding
# one just for expiry sweeping would be a new moving part not required
# by anything else here. An on-read check is simpler, always correct
# at the moment of access (nothing can observe a stale "pending" state
# past its expiry), and needs no extra infrastructure. The lazy
# transition is persisted transactionally on read so the correction
# only happens once and subsequent reads are consistent.

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from registry.models.tables import approval_expiry_config, approval_requests

DEFAULT_EXPIRY_SECS = 5 * 60 * 60  # 5 hours


def _effective_expiry_secs(session: Session, recipient: str, override: int | None) -> int:
    if override is not None:
        return override
    row = session.execute(
        select(approval_expiry_config.c.default_expiry_secs).where(
            approval_expiry_config.c.recipient == recipient
        )
    ).first()
    return row[0] if row else DEFAULT_EXPIRY_SECS


def create_approval_request(
    session: Session,
    sender: str,
    recipient: str,
    candidate_capsule_ids: list[str],
    now: datetime,
    expiry_secs_override: int | None = None,
) -> str:
    expiry_secs = _effective_expiry_secs(session, recipient, expiry_secs_override)
    request_id = str(uuid.uuid4())
    session.execute(
        approval_requests.insert().values(
            id=request_id,
            sender=sender,
            recipient=recipient,
            candidate_capsule_ids=candidate_capsule_ids,
            state="pending",
            created_at=now,
            expires_at=now + timedelta(seconds=expiry_secs),
            resolved_grant_id=None,
        )
    )
    return request_id


def get_approval_request(session: Session, request_id: str, now: datetime):
    """Reads the request, lazily transitioning an unresolved pending
    request past its expiry to 'denied' (auto-deny — an unanswered
    request must never silently grant access, PRD.md §6)."""
    result = session.execute(
        update(approval_requests)
        .where(
            approval_requests.c.id == request_id,
            approval_requests.c.state == "pending",
            approval_requests.c.expires_at <= now,
        )
        .values(state="denied")
        .returning(*approval_requests.c)
    ).mappings().first()
    if result is not None:
        return result
    return (
        session.execute(select(approval_requests).where(approval_requests.c.id == request_id))
        .mappings()
        .first()
    )


def resolve_approval_request(
    session: Session, request_id: str, decision: str, now: datetime, resolved_grant_id: str | None = None
) -> bool:
    """Transitions a still-pending, not-yet-expired request to
    'approved' or 'denied'. Returns False if the request is no longer
    pending (already resolved, or expired — auto-deny already won)."""
    row = get_approval_request(session, request_id, now)
    if row is None or row["state"] != "pending":
        return False
    session.execute(
        update(approval_requests)
        .where(approval_requests.c.id == request_id, approval_requests.c.state == "pending")
        .values(state=decision, resolved_grant_id=resolved_grant_id)
    )
    return True
