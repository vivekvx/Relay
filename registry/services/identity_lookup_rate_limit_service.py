# Per-source-IP rate limiting for the unauthenticated identity-lookup
# endpoints (GET /identities/{handle}, GET /identities/by-relay-number/
# {relay_number}) — same fixed-counter/sliding-1-hour-window pattern as
# rate_limit_service.py, keyed by source IP instead of (sender,
# recipient) since a GET has no signed payload to attribute a caller
# identity from.
#
# DEFAULT_LOOKUP_LIMIT_PER_HOUR = 60 (one lookup/minute, sustained) —
# deliberately much tighter than the 20/hour messaging limit (which is
# per (sender, recipient) PAIR, so one real sender can rack up many
# times 20/hour across several different recipients). A real single-IP
# user doing legitimate lookups (one relay_number/handle resolution per
# ask(), a handful of contacts, whoami, grant/revoke flows) stays well
# under single digits per hour in practice; 60 leaves generous headroom
# for that while still bounding a brute-force enumeration attempt to a
# few dozen guesses/hour per IP — raises the cost of enumerating the
# 2**32 relay_number space or a handle dictionary substantially, though
# it does not eliminate enumeration structurally (see
# registry/ARCHITECTURE.md's tradeoff note).
#
# Not per-recipient-configurable like rate_limit_config: there IS no
# recipient identity yet at lookup time (that's what's being looked
# up), so a registry-operator-wide constant is the only sensible
# default here, not an owner-configurable one.

from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from registry.models.tables import identity_lookup_events

DEFAULT_LOOKUP_LIMIT_PER_HOUR = 60


def check_and_record(
    session: Session, ip: str, now: datetime, limit: int = DEFAULT_LOOKUP_LIMIT_PER_HOUR
) -> bool:
    """Returns True if this lookup is allowed (and records it). Returns
    False if `ip` is over the per-hour limit — the caller must reject
    the request before running the actual lookup."""
    window_start = now - timedelta(hours=1)

    count = session.execute(
        select(func.count()).where(
            identity_lookup_events.c.ip == ip,
            identity_lookup_events.c.occurred_at > window_start,
        )
    ).scalar_one()

    if count >= limit:
        return False

    session.execute(identity_lookup_events.insert().values(ip=ip, occurred_at=now))
    return True
