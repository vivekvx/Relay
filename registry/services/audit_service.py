# Append-only audit log writes. PRD.md §4.2 "Audit trail" — metadata
# only (who/what/when/outcome), never capsule/query/response content.
# The append-only guarantee is enforced structurally at the DB level by
# a trigger (schema.sql, `audit_log_append_only`) that rejects any
# UPDATE/DELETE regardless of caller — this module simply never issues
# one (it only ever INSERTs), and the trigger is the backstop if it
# ever did by mistake.

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from registry.models.tables import audit_log


def record_audit_event(
    session: Session,
    event_type: str,
    outcome: str,
    sender: str | None = None,
    recipient: str | None = None,
    detail: str | None = None,
) -> None:
    session.execute(
        audit_log.insert().values(
            occurred_at=datetime.now(timezone.utc),
            sender=sender,
            recipient=recipient,
            event_type=event_type,
            outcome=outcome,
            detail=detail,
        )
    )
