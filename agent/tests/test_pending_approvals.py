# Unit tests for wiring/pending_approvals.py's PendingApprovalStore —
# pure local state, no registry/identity/approval involved.

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta

from wiring.pending_approvals import PendingApproval, PendingApprovalStore

NOW = datetime(2026, 7, 30, 12, 0, 0)


def make_pending(nonce: str = "n1", expiry_seconds: int = 3600, created_at: datetime = NOW) -> PendingApproval:
    return PendingApproval(
        nonce=nonce, sender="vivek", thread_id="t1", query="why postgres?",
        created_at=created_at.isoformat(), expiry_seconds=expiry_seconds,
        candidate_capsule_ids=["c1"], reusable_capsule_ids=[],
    )


class TestPendingApprovalStore(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".json")

    def test_add_then_list(self):
        store = PendingApprovalStore(self.path)
        store.add(make_pending())
        self.assertEqual(len(store.list()), 1)
        self.assertEqual(store.list()[0].sender, "vivek")

    def test_pop_removes_and_returns(self):
        store = PendingApprovalStore(self.path)
        store.add(make_pending())
        popped = store.pop("n1")
        self.assertIsNotNone(popped)
        self.assertEqual(store.list(), [])

    def test_pop_unknown_returns_none(self):
        store = PendingApprovalStore(self.path)
        self.assertIsNone(store.pop("no-such-nonce"))

    def test_persistence_across_instances(self):
        store = PendingApprovalStore(self.path)
        store.add(make_pending())
        reloaded = PendingApprovalStore(self.path)
        self.assertEqual(len(reloaded.list()), 1)

    def test_pop_expired_removes_only_expired_entries(self):
        store = PendingApprovalStore(self.path)
        store.add(make_pending("fresh", expiry_seconds=3600, created_at=NOW))
        store.add(make_pending("stale", expiry_seconds=60, created_at=NOW))
        later = NOW + timedelta(minutes=30)
        expired = store.pop_expired(later)
        self.assertEqual([e.nonce for e in expired], ["stale"])
        remaining = [item.nonce for item in store.list()]
        self.assertEqual(remaining, ["fresh"])

    def test_to_approval_request_round_trips_fields(self):
        pending = make_pending()
        request = pending.to_approval_request()
        self.assertEqual(request.sender, "vivek")
        self.assertEqual(request.query, "why postgres?")
        self.assertEqual(request.candidate_capsule_ids, ("c1",))


if __name__ == "__main__":
    unittest.main()
