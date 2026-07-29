# Identity registration. PRD.md §4.2 "Identity layer" — registry
# stores public keys + routing metadata only, never private key
# material. Structural defense against accepting non-public-key data:
# RegisterIdentityRequest's Pydantic field pattern (64 lowercase hex
# chars) rejects anything else at the schema layer before this code
# runs; the DB CHECK constraint in schema.sql enforces the same shape
# a second time at the storage layer.

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from registry.models.tables import identities


class DuplicateHandleError(Exception):
    pass


def register_identity(
    session: Session, handle: str, public_key_hex: str, x25519_public_key_hex: str
) -> None:
    existing = session.execute(
        select(identities.c.handle).where(identities.c.handle == handle)
    ).first()
    if existing is not None:
        raise DuplicateHandleError(f"handle {handle!r} is already registered")

    session.execute(
        identities.insert().values(
            handle=handle,
            public_key_hex=public_key_hex,
            x25519_public_key_hex=x25519_public_key_hex,
            created_at=datetime.now(timezone.utc),
        )
    )
    session.commit()


def get_public_key_hex(session: Session, handle: str) -> str | None:
    """Ed25519 signing key — used by relay_service's signature
    verification, unchanged from before this task."""
    row = session.execute(
        select(identities.c.public_key_hex).where(identities.c.handle == handle)
    ).first()
    return row[0] if row else None


def get_x25519_public_key_hex(session: Session, handle: str) -> str | None:
    """X25519 encryption key — for a sender to look up before encrypting
    content for this handle. Not used anywhere in the signature-
    verification path."""
    row = session.execute(
        select(identities.c.x25519_public_key_hex).where(identities.c.handle == handle)
    ).first()
    return row[0] if row else None


def get_identity(session: Session, handle: str):
    return (
        session.execute(select(identities).where(identities.c.handle == handle))
        .mappings()
        .first()
    )


def identity_exists(session: Session, handle: str) -> bool:
    return get_public_key_hex(session, handle) is not None
