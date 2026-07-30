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
import threading
from datetime import datetime, timedelta

from resolver.resolver import DEFAULT_ENUMERATION_WINDOW


class DisclosureLog:
    """sender -> [(capsule_id, at)], one JSON file per local identity."""

    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, list[tuple[str, str]]] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        self._entries = {sender: [(e["capsule_id"], e["at"]) for e in entries] for sender, entries in raw.items()}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        raw = {
            sender: [{"capsule_id": cid, "at": at} for cid, at in entries]
            for sender, entries in self._entries.items()
        }
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)

    def record(self, sender: str, capsule_ids: frozenset[str], now: datetime) -> None:
        if not capsule_ids:
            return
        with self._lock:
            entries = self._entries.setdefault(sender, [])
            entries.extend((cid, now.isoformat()) for cid in sorted(capsule_ids))
            self._save()

    def distinct_capsules_in_window(
        self, sender: str, now: datetime, window: timedelta = DEFAULT_ENUMERATION_WINDOW
    ) -> frozenset[str]:
        with self._lock:
            entries = self._entries.get(sender, [])
        window_start = now - window
        return frozenset(cid for cid, at in entries if datetime.fromisoformat(at) > window_start)
