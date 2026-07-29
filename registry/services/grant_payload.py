# Canonical byte encoding for grant create/revoke requests — what
# actually gets signed for these two operations. Separate from
# canonical_payload.py (identity/src/payload.rs's fixed 5-field
# ask/relay format) because grant operations carry different fields
# (grant_type, scope_capsule_ids, expires_at) that format has no room
# for; extending identity/'s Rust format would mean touching identity/
# itself, out of scope for this fix. Same length-prefix discipline as
# canonical_payload.py, for the same reason: unambiguous field
# boundaries (PRD.md §6, R2 — no request may be authorized by a claimed
# handle string alone; this is what makes grantor/grant_id claims
# provable rather than trusted at face value).

import re
import struct

NONCE_HEX_LEN = 32
_NONCE_RE = re.compile(rf"^[0-9a-f]{{{NONCE_HEX_LEN}}}$")


class GrantPayloadError(ValueError):
    pass


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
    """What a grantor must sign to create a grant. Binds every field the
    server will actually store — an attacker who reuses a valid
    signature/envelope cannot swap in different capsule_ids or a
    different expires_at, since those bytes are inside what was signed."""
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
    """What must be signed to revoke a grant. Deliberately does NOT take
    a grantor field from the caller — the caller (grant_service) looks up
    the grant's actual stored grantor and verifies against THAT identity,
    so a request can't claim a different grantor than the one who
    actually owns the grant being revoked."""
    out = bytearray()
    _write_field(out, grant_id)
    out += struct.pack(">Q", timestamp)
    _write_field(out, nonce)
    return bytes(out)


def is_nonce_well_formed(nonce: str) -> bool:
    return bool(_NONCE_RE.match(nonce))
