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
import threading
from dataclasses import asdict, dataclass

from .registry_client import RegistryClient


@dataclass
class Contact:
    name: str
    relay_number: str


class ContactsStore:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.Lock()
        self._contacts: dict[str, Contact] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        with open(self._path, encoding="utf-8") as f:
            raw = json.load(f)
        self._contacts = {name: Contact(**fields) for name, fields in raw.items()}

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        raw = {name: asdict(contact) for name, contact in self._contacts.items()}
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)

    def add(self, name: str, relay_number: str) -> None:
        with self._lock:
            self._contacts[name] = Contact(name=name, relay_number=relay_number)
            self._save()

    def get(self, name: str) -> Contact | None:
        with self._lock:
            return self._contacts.get(name)

    def list(self) -> list[Contact]:
        with self._lock:
            return sorted(self._contacts.values(), key=lambda c: c.name)

    def remove(self, name: str) -> bool:
        with self._lock:
            existed = self._contacts.pop(name, None) is not None
            if existed:
                self._save()
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
