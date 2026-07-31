# Local, per-identity, cross-thread record of which capsule IDs have
# actually been disclosed (approved-whole or approved-excerpt) to which
# sender — feeds the anti-enumeration guard (PRD.md §5 R3, "salami
# slicing"). Distinct from wiring/threads.py's ThreadStore: a thread's
# approved_capsule_ids is scoped to ONE conversation; this is the
# sender's cumulative footprint against the recipient's ENTIRE capsule
# library, across every thread. Entirely local — never synced anywhere,
# same category as the local audit log (PRD.md §4.2).

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

from resolver.resolver import DEFAULT_ENUMERATION_WINDOW

from .atomic_json_store import atomic_write_json, locked


class DisclosureLog:
    """sender -> [(capsule_id, at)], one JSON file per local identity.

    Every public method re-reads fresh from disk and writes back under
    a single `locked()` critical section (atomic_json_store.py) —
    see wiring/threads.py's ThreadStore docstring for why this matters
    across processes, not just within one (`relay serve`'s background
    poll loop vs. a concurrent manual CLI invocation touching the same
    file)."""

    def __init__(self, path: str):
        self._path = path

    def _load(self) -> dict[str, list[tuple[str, str]]]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        return {sender: [(e["capsule_id"], e["at"]) for e in entries] for sender, entries in raw.items()}

    def _save(self, entries_by_sender: dict[str, list[tuple[str, str]]]) -> None:
        raw = {
            sender: [{"capsule_id": cid, "at": at} for cid, at in entries]
            for sender, entries in entries_by_sender.items()
        }
        atomic_write_json(self._path, raw)

    def record(self, sender: str, capsule_ids: frozenset[str], now: datetime) -> None:
        if not capsule_ids:
            return
        with locked(self._path):
            entries_by_sender = self._load()
            entries = entries_by_sender.setdefault(sender, [])
            entries.extend((cid, now.isoformat()) for cid in sorted(capsule_ids))
            self._save(entries_by_sender)

    def distinct_capsules_in_window(
        self, sender: str, now: datetime, window: timedelta = DEFAULT_ENUMERATION_WINDOW
    ) -> frozenset[str]:
        with locked(self._path):
            entries = self._load().get(sender, [])
        window_start = now - window
        return frozenset(cid for cid, at in entries if datetime.fromisoformat(at) > window_start)
