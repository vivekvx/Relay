# Unit tests for wiring/threads.py's ThreadStore — pure local state, no
# registry/identity/approval involved. Proves persistence across
# instances (a new process re-reading the same file), the never-inherit
# rule for a fresh thread_id, and expiry semantics independent of
# ApprovalRequest's own 5h default.

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from wiring.threads import DEFAULT_THREAD_INACTIVITY_EXPIRY, ThreadStore

NOW = datetime(2026, 7, 30, 12, 0, 0)


class TestThreadStore(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.path = tempfile.mktemp(suffix=".json")

    def test_get_or_create_is_idempotent(self):
        store = ThreadStore(self.path)
        first = store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        second = store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW + timedelta(minutes=5))
        self.assertEqual(first.created_at, second.created_at)  # not overwritten

    def test_add_approved_capsules_accumulates(self):
        store = ThreadStore(self.path)
        store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        store.add_approved_capsules("t1", frozenset({"c1"}))
        store.add_approved_capsules("t1", frozenset({"c2"}))
        self.assertEqual(store.get("t1").approved_capsule_ids, ["c1", "c2"])

    def test_persistence_across_instances(self):
        store = ThreadStore(self.path)
        store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        store.add_approved_capsules("t1", frozenset({"c1"}))

        reloaded = ThreadStore(self.path)  # simulates a fresh process
        record = reloaded.get("t1")
        self.assertIsNotNone(record)
        self.assertEqual(record.approved_capsule_ids, ["c1"])

    def test_fresh_thread_id_never_inherits_another_threads_scope(self):
        store = ThreadStore(self.path)
        store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        store.add_approved_capsules("t1", frozenset({"c1"}))

        fresh = store.get_or_create("t2", sender="vivek", recipient="rohan", now=NOW)
        self.assertEqual(fresh.approved_capsule_ids, [])

    def test_not_expired_within_ttl(self):
        record = ThreadStore(self.path).get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        self.assertFalse(record.is_expired(NOW + timedelta(hours=23)))

    def test_expired_past_ttl(self):
        record = ThreadStore(self.path).get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        self.assertTrue(record.is_expired(NOW + DEFAULT_THREAD_INACTIVITY_EXPIRY))

    def test_record_message_extends_last_activity_and_resets_expiry_clock(self):
        store = ThreadStore(self.path)
        store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        later = NOW + timedelta(hours=23)
        store.record_message("t1", question="q", answer="a", outcome="approved_whole", now=later)
        record = store.get("t1")
        self.assertFalse(record.is_expired(later + timedelta(hours=23)))  # extended from `later`, not NOW

    def test_finalize_message_fills_in_placeholder_by_nonce(self):
        store = ThreadStore(self.path)
        store.get_or_create("t1", sender="vivek", recipient="rohan", now=NOW)
        store.record_message("t1", question="q", answer="", outcome="pending", now=NOW, nonce="n1")
        store.finalize_message("t1", "n1", answer="the answer", outcome="approved_whole", now=NOW)
        record = store.get("t1")
        self.assertEqual(len(record.messages), 1)
        self.assertEqual(record.messages[0].answer, "the answer")
        self.assertEqual(record.messages[0].outcome, "approved_whole")

    def test_finalize_message_on_unknown_thread_is_a_safe_noop(self):
        store = ThreadStore(self.path)
        store.finalize_message("no-such-thread", "n1", answer="x", outcome="approved_whole", now=NOW)  # must not raise


if __name__ == "__main__":
    unittest.main()
