# Grant storage (CRUD). PRD.md §4.2 "Consent-scoped memory" / §6 Grant.
#
# This is storage only. Revocation here just sets `revoked_at` —
# immediately, correctly, queryable. The actual enforcement (checking
# grant validity at capsule-load time, so an in-flight request fails
# under a grant revoked mid-request) is agent/resolver/'s job, not the
# registry's — this module does not reimplement that check-at-load-time
# logic (PRD.md §3.1 step 8). See registry/ARCHITECTURE.md.

import uuid
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from registry.models.tables import grants


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
