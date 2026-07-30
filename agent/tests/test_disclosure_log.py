# Unit tests for wiring/disclosure_log.py's DisclosureLog — pure local
# state, no registry/identity/approval involved. Proves persistence
# across instances, rolling-window expiry, and per-sender isolation
# (the cumulative footprint is per (sender, this recipient), not global).

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta

from wiring.disclosure_log import DisclosureLog

NOW = datetime(2026, 7, 30, 12, 0, 0)


class TestDisclosureLog(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".json")

    def test_record_then_query_returns_distinct_ids(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1", "c2"}), NOW)
        self.assertEqual(log.distinct_capsules_in_window("vivek", NOW), frozenset({"c1", "c2"}))

    def test_recording_same_capsule_twice_stays_distinct(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1"}), NOW)
        log.record("vivek", frozenset({"c1"}), NOW + timedelta(days=1))
        self.assertEqual(log.distinct_capsules_in_window("vivek", NOW + timedelta(days=2)), frozenset({"c1"}))

    def test_entries_outside_window_are_excluded(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1"}), NOW)
        later = NOW + timedelta(days=31)
        self.assertEqual(log.distinct_capsules_in_window("vivek", later, window=timedelta(days=30)), frozenset())

    def test_entries_inside_window_are_included(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1"}), NOW)
        later = NOW + timedelta(days=29)
        self.assertEqual(log.distinct_capsules_in_window("vivek", later, window=timedelta(days=30)), frozenset({"c1"}))

    def test_senders_are_isolated(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1"}), NOW)
        log.record("priya", frozenset({"c2"}), NOW)
        self.assertEqual(log.distinct_capsules_in_window("vivek", NOW), frozenset({"c1"}))
        self.assertEqual(log.distinct_capsules_in_window("priya", NOW), frozenset({"c2"}))

    def test_unknown_sender_returns_empty(self):
        log = DisclosureLog(self.path)
        self.assertEqual(log.distinct_capsules_in_window("nobody", NOW), frozenset())

    def test_persistence_across_instances(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset({"c1"}), NOW)

        reloaded = DisclosureLog(self.path)  # simulates a fresh process
        self.assertEqual(reloaded.distinct_capsules_in_window("vivek", NOW), frozenset({"c1"}))

    def test_recording_empty_set_is_a_noop(self):
        log = DisclosureLog(self.path)
        log.record("vivek", frozenset(), NOW)
        self.assertEqual(log.distinct_capsules_in_window("vivek", NOW), frozenset())


if __name__ == "__main__":
    unittest.main()
