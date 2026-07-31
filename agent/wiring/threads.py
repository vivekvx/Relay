# Conversation/thread state for multi-turn `relay ask` — entirely
# local, per-identity, never synced to the registry. A thread_id travels
# only inside the already end-to-end-encrypted `content_ciphertext`
# payload (same channel the response envelope's `in_reply_to_nonce`
# already uses) — the registry has no field for it and never sees it,
# so the "registry must never see capsule content" boundary
# (CLAUDE.md §2, registry/ARCHITECTURE.md) needs no new carve-out here.
#
# What's stored, and why it's safe to store locally in plaintext:
# thread_id, participant handles, question/answer text, and the set of
# capsule IDs already approved within this thread. This is the same
# category of thing the local audit log already records (PRD.md §4.2
# "Audit trail") — it lives only on each party's own machine, same as
# the capsule store itself.

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from .atomic_json_store import atomic_write_json, locked

DEFAULT_THREAD_INACTIVITY_EXPIRY = timedelta(hours=24)


@dataclass
class ThreadMessage:
    question: str
    answer: str
    outcome: str
    at: str  # isoformat
    nonce: str = ""  # asker-side only: lets a later ask_response fill in a placeholder


@dataclass
class ThreadRecord:
    thread_id: str
    sender: str  # who asks in this conversation
    recipient: str  # who answers in this conversation
    created_at: str  # isoformat
    last_activity_at: str  # isoformat
    approved_capsule_ids: list[str] = field(default_factory=list)
    messages: list[ThreadMessage] = field(default_factory=list)

    def is_expired(self, now: datetime, ttl: timedelta = DEFAULT_THREAD_INACTIVITY_EXPIRY) -> bool:
        """Inactivity expiry, independent of any single ApprovalRequest's
        own 5h expiry_duration (resolver.types.ApprovalRequest) — a
        conversation going quiet for 24h does not retroactively undo any
        approval already granted, it only stops that approval from being
        silently reused by a later message; see effective_approved_ids
        in flows.process_incoming_ask."""
        return now - datetime.fromisoformat(self.last_activity_at) >= ttl


class ThreadStore:
    """thread_id -> ThreadRecord, one JSON file per local identity.

    Every public method here re-reads the file fresh from disk and
    writes it back, all under a single `locked()` critical section
    (atomic_json_store.py) — not just cached in memory and flushed on
    write. `relay serve`'s long-lived background poll loop and a
    concurrent manual `relay ask`/`relay pending` invocation are two
    independent processes that can genuinely touch this same file at
    the same moment; without re-reading under a lock, the second
    writer's save would silently clobber the first's change using a
    stale in-memory copy. The lock also covers ordinary same-process
    thread-safety (each call opens its own fd/lock, so concurrent
    threads in one process serialize the same way concurrent processes
    do) — no separate threading.Lock needed."""

    def __init__(self, path: str):
        self._path = path

    def _load(self) -> dict[str, ThreadRecord]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        records: dict[str, ThreadRecord] = {}
        for thread_id, rec in raw.items():
            messages = [ThreadMessage(**m) for m in rec.get("messages", [])]
            records[thread_id] = ThreadRecord(
                thread_id=rec["thread_id"],
                sender=rec["sender"],
                recipient=rec["recipient"],
                created_at=rec["created_at"],
                last_activity_at=rec["last_activity_at"],
                approved_capsule_ids=list(rec.get("approved_capsule_ids", [])),
                messages=messages,
            )
        return records

    def _save(self, records: dict[str, ThreadRecord]) -> None:
        atomic_write_json(self._path, {thread_id: asdict(rec) for thread_id, rec in records.items()})

    def get(self, thread_id: str) -> ThreadRecord | None:
        with locked(self._path):
            return self._load().get(thread_id)

    def get_or_create(self, thread_id: str, sender: str, recipient: str, now: datetime) -> ThreadRecord:
        """Never overwrites an existing record — an inactivity-expired
        thread keeps its history and its thread_id; only its
        approved_capsule_ids stop being trusted for auto-continuation
        (see flows.py's effective_approved_ids), not its identity or log."""
        with locked(self._path):
            records = self._load()
            existing = records.get(thread_id)
            if existing is not None:
                return existing
            record = ThreadRecord(
                thread_id=thread_id,
                sender=sender,
                recipient=recipient,
                created_at=now.isoformat(),
                last_activity_at=now.isoformat(),
            )
            records[thread_id] = record
            self._save(records)
            return record

    def add_approved_capsules(self, thread_id: str, capsule_ids: frozenset[str]) -> None:
        if not capsule_ids:
            return
        with locked(self._path):
            records = self._load()
            record = records[thread_id]
            record.approved_capsule_ids = sorted(set(record.approved_capsule_ids) | capsule_ids)
            self._save(records)

    def record_message(
        self, thread_id: str, question: str, answer: str, outcome: str, now: datetime, nonce: str = ""
    ) -> None:
        with locked(self._path):
            records = self._load()
            record = records[thread_id]
            record.messages.append(
                ThreadMessage(question=question, answer=answer, outcome=outcome, at=now.isoformat(), nonce=nonce)
            )
            record.last_activity_at = now.isoformat()
            self._save(records)

    def finalize_message(self, thread_id: str, nonce: str, answer: str, outcome: str, now: datetime) -> None:
        """Fills in a placeholder message ask() recorded at send time
        (question known, answer not yet) once the answer arrives —
        possibly out-of-band, via a later poll cycle in a different
        process than the one that called ask(). No-op if the thread or
        the placeholder no longer exists (e.g. a fresh CLI process
        running `relay check` with no in-memory history of its own
        ask() call) rather than raising — nothing security-relevant
        depends on this bookkeeping succeeding."""
        with locked(self._path):
            records = self._load()
            record = records.get(thread_id)
            if record is None:
                return
            record.last_activity_at = now.isoformat()
            for message in record.messages:
                if message.nonce == nonce:
                    message.answer = answer
                    message.outcome = outcome
                    self._save(records)
                    return
            record.messages.append(
                ThreadMessage(question="", answer=answer, outcome=outcome, at=now.isoformat(), nonce=nonce)
            )
            self._save(records)
