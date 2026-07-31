# Local, per-identity contacts: a memorable local name -> an opaque
# "relay number" (never the other person's handle itself — the routing
# id doesn't leak who someone is just by looking at it, same trust
# model as a phone number). Strictly local and per-person; added
# manually by exchanging relay numbers out of band (this task's
# explicit DO NOT BUILD — no public/global directory).
#
# Entirely local, never synced to the registry — same category as
# wiring/threads.py's ThreadStore.

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from .atomic_json_store import atomic_write_json, locked
from .registry_client import RegistryClient


@dataclass
class Contact:
    name: str
    relay_number: str


class ContactsStore:
    """Every public method re-reads fresh from disk and writes back
    under a single `locked()` critical section (atomic_json_store.py) —
    see wiring/threads.py's ThreadStore docstring for why this matters
    across processes, not just within one."""

    def __init__(self, path: str):
        self._path = path

    def _load(self) -> dict[str, Contact]:
        if not os.path.exists(self._path):
            return {}
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        return {name: Contact(**fields) for name, fields in raw.items()}

    def _save(self, contacts: dict[str, Contact]) -> None:
        atomic_write_json(self._path, {name: asdict(contact) for name, contact in contacts.items()})

    def add(self, name: str, relay_number: str) -> None:
        with locked(self._path):
            contacts = self._load()
            contacts[name] = Contact(name=name, relay_number=relay_number)
            self._save(contacts)

    def get(self, name: str) -> Contact | None:
        with locked(self._path):
            return self._load().get(name)

    def list(self) -> list[Contact]:
        with locked(self._path):
            return sorted(self._load().values(), key=lambda c: c.name)

    def remove(self, name: str) -> bool:
        with locked(self._path):
            contacts = self._load()
            existed = contacts.pop(name, None) is not None
            if existed:
                self._save(contacts)
            return existed


def resolve_recipient(contacts: ContactsStore, registry: RegistryClient, name_or_handle: str) -> str:
    """If `name_or_handle` matches a saved contact, resolves it to the
    underlying handle via the registry's relay-number lookup; otherwise
    returns it unchanged as a raw handle — additive, never breaks
    existing direct-handle usage (this task's explicit requirement).

    Raises ValueError if a saved contact's relay_number is no longer
    registered — fails loud rather than silently falling back to
    treating the local contact NAME as if it were itself a handle
    (those are different namespaces; treating one as the other would be
    a routing mistake, not a safe default)."""
    contact = contacts.get(name_or_handle)
    if contact is None:
        return name_or_handle
    identity = registry.get_identity_by_relay_number(contact.relay_number)
    if identity is None:
        raise ValueError(
            f"contact {name_or_handle!r}'s relay number is no longer registered — "
            f"ask them for their current relay number and `relay contacts add` it again"
        )
    return identity["handle"]
