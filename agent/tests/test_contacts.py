# Unit tests for wiring/contacts.py — pure local state (ContactsStore)
# plus resolve_recipient's resolution logic, using a minimal fake
# registry rather than a real one (no network/DB needed for this logic).

from __future__ import annotations

import tempfile
import unittest

from wiring.contacts import ContactsStore, resolve_recipient


class FakeRegistry:
    def __init__(self, by_relay_number: dict):
        self._by_relay_number = by_relay_number

    def get_identity_by_relay_number(self, relay_number):
        return self._by_relay_number.get(relay_number)


class TestContactsStore(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".json")

    def test_add_then_list(self):
        store = ContactsStore(self.path)
        store.add("friend", "abcd1234")
        self.assertEqual([c.name for c in store.list()], ["friend"])
        self.assertEqual(store.get("friend").relay_number, "abcd1234")

    def test_list_is_sorted_by_name(self):
        store = ContactsStore(self.path)
        store.add("zed", "11111111")
        store.add("amy", "22222222")
        self.assertEqual([c.name for c in store.list()], ["amy", "zed"])

    def test_remove_existing_returns_true(self):
        store = ContactsStore(self.path)
        store.add("friend", "abcd1234")
        self.assertTrue(store.remove("friend"))
        self.assertIsNone(store.get("friend"))

    def test_remove_unknown_returns_false(self):
        store = ContactsStore(self.path)
        self.assertFalse(store.remove("nobody"))

    def test_persistence_across_instances(self):
        store = ContactsStore(self.path)
        store.add("friend", "abcd1234")
        reloaded = ContactsStore(self.path)
        self.assertEqual(reloaded.get("friend").relay_number, "abcd1234")

    def test_contact_never_stores_a_handle_field(self):
        # Structural check on the deliberate design choice: Contact only
        # ever has name/relay_number — there is no field a handle could
        # even be written into.
        store = ContactsStore(self.path)
        store.add("friend", "abcd1234")
        contact = store.get("friend")
        self.assertEqual(vars(contact).keys(), {"name", "relay_number"})


class TestResolveRecipient(unittest.TestCase):
    def setUp(self):
        self.path = tempfile.mktemp(suffix=".json")

    def test_saved_contact_resolves_to_handle_via_registry(self):
        store = ContactsStore(self.path)
        store.add("friend", "abcd1234")
        registry = FakeRegistry({"abcd1234": {"handle": "rohan"}})
        self.assertEqual(resolve_recipient(store, registry, "friend"), "rohan")

    def test_raw_handle_passes_through_unchanged(self):
        store = ContactsStore(self.path)
        registry = FakeRegistry({})
        self.assertEqual(resolve_recipient(store, registry, "rohan"), "rohan")

    def test_stale_relay_number_raises_not_silently_falls_back(self):
        store = ContactsStore(self.path)
        store.add("friend", "deadbeef")
        registry = FakeRegistry({})  # relay number no longer registered
        with self.assertRaises(ValueError):
            resolve_recipient(store, registry, "friend")


if __name__ == "__main__":
    unittest.main()
