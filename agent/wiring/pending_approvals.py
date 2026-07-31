# Queued ad hoc approval requests awaiting a human decision — the piece
# that makes `relay serve` (headless, no visible terminal) possible.
# `wiring/flows.py`'s process_incoming_ask, when given a
# PendingApprovalStore, enqueues here INSTEAD OF blocking on
# approval.request_approval's terminal input(); `relay pending` is the
# only place that later calls request_approval against these, using the
# exact same interactive UI as the always-had-a-terminal `relay listen`
# path — nothing about the approval UI itself changes for headless mode,
# only when it runs.
#
# Local-only, one JSON file per identity — same category as
# wiring/threads.py's ThreadStore and wiring/disclosure_log.py's
# DisclosureLog (never synced to the registry, CLAUDE.md §2/§3).

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from resolver.types import ApprovalRequest, ApprovalState

from .atomic_json_store import atomic_write_json, locked


@dataclass
class PendingApproval:
    """Everything resolve_pending_approval (flows.py) needs to replay
    the exact same ApprovalRequest a live `relay listen` would have
    built, plus the bookkeeping (thread_id/nonce/reusable ids) that
    process_incoming_ask's CASE B branch already computed before
    queuing — recomputing any of it later would risk drifting from what
    the sender was actually told/asked."""

    nonce: str  # keys the eventual ask_response back to the original ask()
    sender: str
    thread_id: str
    query: str
    created_at: str  # isoformat
    expiry_seconds: int
    candidate_capsule_ids: list[str] = field(default_factory=list)
    reusable_capsule_ids: list[str] = field(default_factory=list)
    reason: str = ""
    urgency: str = ""
    enumeration_warning: str | None = None

    def to_approval_request(self) -> ApprovalRequest:
        return ApprovalRequest(
            sender=self.sender,
            query=self.query,
            created_at=datetime.fromisoformat(self.created_at),
            expiry_duration=timedelta(seconds=self.expiry_seconds),
            candidate_capsule_ids=tuple(self.candidate_capsule_ids),
            state=ApprovalState.PENDING,
            reason=self.reason,
            urgency=self.urgency,
            enumeration_warning=self.enumeration_warning,
        )

    def is_expired(self, now: datetime) -> bool:
        return self.to_approval_request().resolved_state(now) is ApprovalState.DENIED


class PendingApprovalStore:
    """Every public method re-reads fresh from disk and writes back
    under a single `locked()` critical section (atomic_json_store.py) —
    see wiring/threads.py's ThreadStore docstring for why this matters
    across processes, not just within one."""

    def __init__(self, path: str):
        self._path = path

    def _load(self) -> dict[str, PendingApproval]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        return {nonce: PendingApproval(**fields) for nonce, fields in raw.items()}

    def _save(self, items: dict[str, PendingApproval]) -> None:
        atomic_write_json(self._path, {nonce: asdict(item) for nonce, item in items.items()})

    def add(self, pending: PendingApproval) -> None:
        with locked(self._path):
            items = self._load()
            items[pending.nonce] = pending
            self._save(items)

    def list(self) -> list[PendingApproval]:
        with locked(self._path):
            return list(self._load().values())

    def get(self, nonce: str) -> PendingApproval | None:
        with locked(self._path):
            return self._load().get(nonce)

    def pop(self, nonce: str) -> PendingApproval | None:
        with locked(self._path):
            items = self._load()
            item = items.pop(nonce, None)
            if item is not None:
                self._save(items)
            return item

    def pop_expired(self, now: datetime) -> list[PendingApproval]:
        """Removes and returns every entry past its own expiry — the
        caller (flows.sweep_expired_pending_approvals) is responsible
        for actually sending the auto-deny response for each one. This
        method only owns store state, never wire I/O (same separation
        every other store in wiring/ keeps)."""
        with locked(self._path):
            items = self._load()
            expired = [item for item in items.values() if item.is_expired(now)]
            for item in expired:
                del items[item.nonce]
            if expired:
                self._save(items)
            return expired
