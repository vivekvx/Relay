# Fixed-counter rate limiting: N queries per (sender, recipient) per
# hour. PRD.md §5 R3 — default 20/hour, overridable per-recipient (the
# capsule owner configures their own limit). Sliding 1-hour window over
# an event log, consistent with agent/resolver/rate_limiter.py's
# approach (same design, different storage — Postgres here vs.
# in-memory there, since this is the hosted, multi-process component).

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from registry.models.tables import rate_limit_config, rate_limit_events

DEFAULT_LIMIT_PER_HOUR = 20


def _effective_limit(session: Session, recipient: str) -> int:
    row = session.execute(
        select(rate_limit_config.c.limit_per_hour).where(
            rate_limit_config.c.recipient == recipient
        )
    ).first()
    return row[0] if row else DEFAULT_LIMIT_PER_HOUR


def check_and_record(session: Session, sender: str, recipient: str, now: datetime) -> bool:
    """Returns True if this query is allowed (and records it). Returns
    False if (sender, recipient) is over the recipient's configured
    per-hour limit."""
    limit = _effective_limit(session, recipient)
    window_start = now - timedelta(hours=1)

    count = session.execute(
        select(func.count()).where(
            rate_limit_events.c.sender == sender,
            rate_limit_events.c.recipient == recipient,
            rate_limit_events.c.occurred_at > window_start,
        )
    ).scalar_one()

    if count >= limit:
        return False

    session.execute(
        rate_limit_events.insert().values(sender=sender, recipient=recipient, occurred_at=now)
    )
    return True


def set_recipient_limit(session: Session, recipient: str, limit_per_hour: int) -> None:
    """Recipient/capsule-owner configures their own limit — already-
    decided pattern, not a new knob."""
    stmt = pg_insert(rate_limit_config).values(
        recipient=recipient, limit_per_hour=limit_per_hour
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[rate_limit_config.c.recipient],
        set_={"limit_per_hour": limit_per_hour},
    )
    session.execute(stmt)
