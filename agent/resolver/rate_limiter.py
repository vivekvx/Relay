# Fixed-counter rate limiter: N queries per sender per hour.
# PRD.md §5 R3 — default 20/hour, configurable by the capsule owner.
# Permanent design at this scale, not a placeholder (no Redis; see
# CLAUDE.md §4). Sliding one-hour window via timestamps.
#
# ponytail: in-memory dict, single-process — persistence/sharing across
# processes is a later concern if this ever needs to survive a restart.

from __future__ import annotations

from datetime import datetime, timedelta

DEFAULT_LIMIT_PER_HOUR = 20


class RateLimiter:
    def __init__(self, default_limit: int = DEFAULT_LIMIT_PER_HOUR):
        self.default_limit = default_limit
        self._history: dict[str, list[datetime]] = {}

    def check_and_record(
        self, sender: str, now: datetime, limit: int | None = None
    ) -> bool:
        """Returns True if this query is allowed (and records it). Returns
        False if the sender is over their per-hour limit — the caller
        must reject the request before scope resolution proceeds (R3)."""
        effective_limit = self.default_limit if limit is None else limit
        window_start = now - timedelta(hours=1)
        history = self._history.setdefault(sender, [])
        history[:] = [t for t in history if t > window_start]
        if len(history) >= effective_limit:
            return False
        history.append(now)
        return True
