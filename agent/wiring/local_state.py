# Local, per-machine state this task owns: loading/creating this
# identity's own keys (via the real relay_identity PyO3 bridge — no
# reimplementation, per this task's instructions), and a minimal
# capsule loader.
#
# ponytail: agent/capsules/ is still a docstring-only stub (no loader
# built). Per this task's explicit scope, capsule loading here is the
# simplest possible direct file read, flagged as a stand-in — NOT a
# reimplementation of whatever agent/capsules/ is eventually meant to
# be (markdown + SQLite/FTS5, PRD.md §4.2). See agent/ARCHITECTURE.md.

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import relay_identity as ri
from resolver.types import Capsule

# ---------------------------------------------------------------------
# Local identity: this machine's own signing + encryption keypairs.
# ---------------------------------------------------------------------


@dataclass
class LocalIdentity:
    handle: str
    private_key: "ri.PrivateKeyMaterial"
    public_key_hex: str
    encryption_key: "ri.EncryptionKeyMaterial"
    encryption_public_key_hex: str

    @classmethod
    def load_or_create(cls, handle: str, key_dir: str) -> "LocalIdentity":
        Path(key_dir).mkdir(parents=True, exist_ok=True)
        signing_store = ri.KeyStore(f"{key_dir}/{handle}.signing.key")
        encryption_store = ri.EncryptionKeyStore(f"{key_dir}/{handle}.encryption.key")

        if signing_store.exists():
            private_key = signing_store.load_private_key()
            public_key_hex = private_key.verifying_key_hex()
        else:
            private_key, public_key_hex = ri.generate_keypair()
            signing_store.save_private_key(private_key)

        if encryption_store.exists():
            encryption_key = encryption_store.load_private_key()
            encryption_public_key_hex = encryption_key.public_key_hex()
        else:
            encryption_key, encryption_public_key_hex = ri.generate_encryption_keypair()
            encryption_store.save_private_key(encryption_key)

        return cls(
            handle=handle,
            private_key=private_key,
            public_key_hex=public_key_hex,
            encryption_key=encryption_key,
            encryption_public_key_hex=encryption_public_key_hex,
        )


# ---------------------------------------------------------------------
# Capsule loading — minimal stand-in, direct file read only.
# ---------------------------------------------------------------------
#
# File format (this task's own invention, documented as a stand-in):
# key: value frontmatter lines, a blank line, then the capsule content.
#
#   id: cap-a
#   shareable: true
#   shareable_with: vivek,priya
#   tags: webhook,retry
#
#   Use exponential backoff with jitter for webhook retries.


def load_capsules(capsule_dir: str) -> dict[str, Capsule]:
    capsules: dict[str, Capsule] = {}
    directory = Path(capsule_dir)
    if not directory.exists():
        return capsules

    for path in sorted(directory.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        header, _, content = text.partition("\n\n")

        fields: dict[str, str] = {}
        for line in header.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

        capsule_id = fields.get("id", path.stem)
        if fields.get("shareable", "").lower() != "true":
            continue  # never eligible unless explicitly marked (PRD.md §2, §5 R4)

        shareable_with = frozenset(
            h.strip() for h in fields.get("shareable_with", "").split(",") if h.strip()
        )
        tags = frozenset(t.strip() for t in fields.get("tags", "").split(",") if t.strip())

        capsules[capsule_id] = Capsule(
            id=capsule_id,
            shareable=True,
            shareable_with=shareable_with,
            tags=tags,
            content=content,
        )
    return capsules


# ---------------------------------------------------------------------
# Grant canonical payload — mirrors registry/services/grant_payload.py
# byte-for-byte (proven by test_integration.py cross-checking against
# that actual module). Duplicated here, not imported, because agent/
# and registry/ are separate deployable processes communicating only
# over HTTP (CLAUDE.md §3) — agent/ must not depend on registry/'s
# source at runtime, same category of necessary duplication as
# registry/services/canonical_payload.py already is for identity/'s
# Rust format (see registry/ARCHITECTURE.md judgment call #1).
# ---------------------------------------------------------------------


def _write_field(out: bytearray, value: str) -> None:
    b = value.encode("utf-8")
    out += struct.pack(">I", len(b))
    out += b


def encode_grant_create_payload(
    grantor: str,
    grantee: str,
    grant_type: str,
    scope_capsule_ids: list[str],
    expires_at_ts: int | None,
    timestamp: int,
    nonce: str,
) -> bytes:
    out = bytearray()
    _write_field(out, grantor)
    _write_field(out, grantee)
    _write_field(out, grant_type)
    out += struct.pack(">I", len(scope_capsule_ids))
    for capsule_id in scope_capsule_ids:
        _write_field(out, capsule_id)
    out += struct.pack(">B", 0 if expires_at_ts is None else 1)
    out += struct.pack(">Q", expires_at_ts or 0)
    out += struct.pack(">Q", timestamp)
    _write_field(out, nonce)
    return bytes(out)


def encode_grant_revoke_payload(grant_id: str, timestamp: int, nonce: str) -> bytes:
    out = bytearray()
    _write_field(out, grant_id)
    out += struct.pack(">Q", timestamp)
    _write_field(out, nonce)
    return bytes(out)
