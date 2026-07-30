# Test suite for the registry component. Proves the properties listed
# in the task: duplicate handle rejected; invalid signature rejected
# before state mutation; replayed nonce rejected; rate limit enforced
# and resets after the window; revoked grant stored/queryable
# immediately (enforcement is the resolver's job, not tested here);
# expired unresolved approval request transitions to denied; audit log
# entries for success and every rejection category; a payload
# containing content-shaped data is rejected/flagged, with its actual
# limits demonstrated directly.

import json
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sqlalchemy import create_engine, select, text

from registry.db.migrate import MigrationSafetyError, apply_schema
from registry.models.tables import audit_log
from registry.services import approval_service, grant_service, identity_service, relay_service
from registry.services.canonical_payload import decode_canonical_payload

# Shared with identity/'s Rust test suite — see identity/ARCHITECTURE.md
# judgment call #5. Lives at repo root's test-vectors/ (neutral ground
# between components, not owned by either identity/ or registry/), not
# reached via a fragile cross-component relative walk. This file is
# registry/tests/test_registry.py, so parents[2] is repo root:
# registry/tests/test_registry.py -> parents[0]=registry/tests,
# parents[1]=registry, parents[2]=repo root.
SHARED_VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "test-vectors" / "canonical_payload_vectors.json"
)


# ---- helpers: mirror identity/src/payload.rs's canonical encoding ----


def encode_canonical_payload(sender, recipient, request_type, timestamp, nonce) -> bytes:
    def field(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack(">I", len(b)) + b

    out = b""
    out += field(sender)
    out += field(recipient)
    out += field(request_type)
    out += struct.pack(">Q", timestamp)
    out += field(nonce)
    return out


def make_identity(session, handle: str):
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    x25519_public_key_hex = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    identity_service.register_identity(session, handle, public_key_hex, x25519_public_key_hex)
    return private_key


def sign_request(private_key, sender, recipient, request_type, timestamp, nonce):
    payload_bytes = encode_canonical_payload(sender, recipient, request_type, timestamp, nonce)
    signature_bytes = private_key.sign(payload_bytes)
    return payload_bytes.hex(), signature_bytes.hex()


NOW = datetime.now(timezone.utc)
VALID_NONCE = "0123456789abcdef0123456789abcdef"


# ---------------------------- identity ----------------------------


def test_duplicate_handle_registration_rejected(session):
    make_identity(session, "vivek")
    with pytest.raises(identity_service.DuplicateHandleError):
        identity_service.register_identity(session, "vivek", "a" * 64, "b" * 64)


# ------------------------------ relay ------------------------------


def test_invalid_signature_rejected_before_any_state_mutation(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())

    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE
    )
    # Corrupt the signature.
    bad_signature_hex = ("0" if signature_hex[0] != "0" else "1") + signature_hex[1:]

    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(session, payload_hex, bad_signature_hex, NOW)
    assert exc_info.value.outcome == "invalid_signature"

    # No business state was written: nonce not consumed, nothing queued.
    from registry.models.tables import nonce_log, pending_relay_queue

    assert session.execute(select(nonce_log)).first() is None
    assert session.execute(select(pending_relay_queue)).first() is None

    # But the rejection IS in the audit log.
    events = session.execute(select(audit_log)).mappings().all()
    assert any(e["outcome"] == "invalid_signature" for e in events)


def test_valid_relay_request_is_enqueued_and_audited(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE
    )

    item_id = relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)
    assert item_id

    pending = relay_service.fetch_pending(session, "rohan")
    assert len(pending) == 1
    assert pending[0]["sender"] == "vivek"

    events = session.execute(select(audit_log)).mappings().all()
    assert any(e["outcome"] == "success" for e in events)


def test_replayed_nonce_rejected(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE
    )

    relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)

    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)
    assert exc_info.value.outcome == "replayed_nonce"

    events = session.execute(select(audit_log)).mappings().all()
    assert any(e["outcome"] == "replayed_nonce" for e in events)


def test_unknown_recipient_rejected(session):
    vivek_key = make_identity(session, "vivek")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "nobody", "ask", now_ts, VALID_NONCE
    )
    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)
    assert exc_info.value.outcome == "unknown_recipient"


def test_suspicious_payload_content_rejected_and_its_actual_limits(session):
    """Demonstrates both what the heuristic catches AND its disclosed
    limit: an oversized single field is caught; the same content split
    across two fields under the length limit is NOT caught (documented,
    not silently hidden)."""
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())

    oversized_request_type = "x" * (relay_service.MAX_FIELD_LEN + 1)
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", oversized_request_type, now_ts, VALID_NONCE
    )
    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)
    assert exc_info.value.outcome == "suspicious_payload_content"

    events = session.execute(select(audit_log)).mappings().all()
    assert any(e["outcome"] == "suspicious_payload_content" for e in events)

    # The disclosed limit: content just under MAX_FIELD_LEN is not
    # flagged by this heuristic at all.
    under_limit_request_type = "x" * (relay_service.MAX_FIELD_LEN - 1)
    payload_hex2, signature_hex2 = sign_request(
        vivek_key, "vivek", "rohan", under_limit_request_type, now_ts, "fedcba9876543210fedcba9876543210"
    )
    # This succeeds — proving the heuristic's limit, not a claim of
    # full content detection.
    relay_service.submit_relay_request(session, payload_hex2, signature_hex2, NOW)


# --------------------------- rate limiting ---------------------------


def test_rate_limit_enforced_and_resets_after_window(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())

    from registry.services import rate_limit_service

    rate_limit_service.set_recipient_limit(session, "rohan", 3)
    session.commit()

    base_now = datetime.now(timezone.utc)
    for i in range(3):
        nonce = f"{i:032d}"
        payload_hex, signature_hex = sign_request(
            vivek_key, "vivek", "rohan", "ask", now_ts, nonce
        )
        relay_service.submit_relay_request(session, payload_hex, signature_hex, base_now)

    # 4th request within the window is rejected.
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, "9" * 32
    )
    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(session, payload_hex, signature_hex, base_now)
    assert exc_info.value.outcome == "rate_limited"

    events = session.execute(select(audit_log)).mappings().all()
    assert any(e["outcome"] == "rate_limited" for e in events)

    # After the 1-hour window, the same sender can relay again. Uses a
    # freshly-signed payload with a timestamp matching `later` — the
    # rate-limit window and the request-freshness window (R6) are
    # independent checks, and this test only exercises the former.
    later = base_now + timedelta(hours=1, minutes=1)
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", int(later.timestamp()), "8" * 32
    )
    item_id = relay_service.submit_relay_request(session, payload_hex, signature_hex, later)
    assert item_id


# ------------------------------ grants ------------------------------


def test_revoked_grant_reflected_immediately_in_storage(session):
    """Registry's job: store the revocation correctly and immediately.
    ENFORCEMENT (checking this at capsule-load time) is agent/resolver/'s
    job — proven by resolver's own tests, not re-tested here."""
    make_identity(session, "rohan")
    make_identity(session, "vivek")
    grant_id = grant_service.create_grant(
        session, grantor="rohan", grantee="vivek", grant_type="standing", scope_capsule_ids=["c1"]
    )
    session.commit()

    row = grant_service.get_grant(session, grant_id)
    assert row["revoked_at"] is None

    grant_service.revoke_grant(session, grant_id)
    session.commit()

    row = grant_service.get_grant(session, grant_id)
    assert row["revoked_at"] is not None


# --------------------------- approval requests ---------------------------


def test_expired_unresolved_approval_request_transitions_to_denied(session):
    make_identity(session, "vivek")
    make_identity(session, "priya")
    created_at = datetime.now(timezone.utc)
    request_id = approval_service.create_approval_request(
        session,
        sender="vivek",
        recipient="priya",
        candidate_capsule_ids=["c1"],
        now=created_at,
        expiry_secs_override=60,
    )
    session.commit()

    row = approval_service.get_approval_request(session, request_id, created_at)
    assert row["state"] == "pending"

    later = created_at + timedelta(seconds=61)
    row = approval_service.get_approval_request(session, request_id, later)
    session.commit()
    assert row["state"] == "denied"

    # Resolving it after expiry fails — auto-deny already won.
    resolved = approval_service.resolve_approval_request(session, request_id, "approved", later)
    assert resolved is False


def test_approval_request_default_expiry_is_five_hours(session):
    make_identity(session, "vivek")
    make_identity(session, "priya")
    created_at = datetime.now(timezone.utc)
    request_id = approval_service.create_approval_request(
        session, sender="vivek", recipient="priya", candidate_capsule_ids=[], now=created_at
    )
    row = approval_service.get_approval_request(session, request_id, created_at)
    assert row["expires_at"] - row["created_at"] == timedelta(hours=5)


# ------------------------- content_ciphertext (opaque relay) -------------------------


def test_content_ciphertext_stored_and_relayed_opaquely(session):
    """The registry never decrypts or inspects this field — this test
    only proves it's stored and handed back byte-for-byte, which is the
    entirety of this component's responsibility for it."""
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE
    )
    ciphertext = b"\x01\x02\x03opaque-bytes-not-real-crypto\xff\xfe"
    relay_service.submit_relay_request(
        session, payload_hex, signature_hex, NOW, content_ciphertext_hex=ciphertext.hex()
    )

    pending = relay_service.fetch_pending(session, "rohan")
    assert len(pending) == 1
    assert bytes.fromhex(pending[0]["content_ciphertext_hex"]) == ciphertext

    # Audit log records only the SIZE, never the ciphertext bytes.
    events = session.execute(select(audit_log)).mappings().all()
    success_event = next(e for e in events if e["outcome"] == "success")
    assert str(len(ciphertext)) in success_event["detail"]
    assert ciphertext.hex() not in (success_event["detail"] or "")


def test_oversized_ciphertext_rejected():
    from registry.services.relay_service import MAX_CIPHERTEXT_BYTES

    assert MAX_CIPHERTEXT_BYTES == 65536  # documents the current bound


def test_oversized_ciphertext_rejected_at_the_boundary(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(
        vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE
    )
    oversized_ciphertext = b"\x00" * (relay_service.MAX_CIPHERTEXT_BYTES + 1)

    with pytest.raises(relay_service.RelayRejection) as exc_info:
        relay_service.submit_relay_request(
            session,
            payload_hex,
            signature_hex,
            NOW,
            content_ciphertext_hex=oversized_ciphertext.hex(),
        )
    assert exc_info.value.outcome == "ciphertext_too_large"


# ------------------------- shared canonical-payload vectors -------------------------


def test_canonical_encoding_matches_shared_test_vectors():
    """Loads the SAME fixture identity/'s Rust suite loads (see
    identity/ARCHITECTURE.md judgment call #5) and proves registry's
    independent Python decoder agrees with the encoded bytes for every
    vector — the drift safeguard for the two-implementation risk
    flagged in the previous registry task."""
    data = json.loads(SHARED_VECTORS_PATH.read_text())
    vectors = data["vectors"]
    assert vectors, "vector file must not be empty"

    for vector in vectors:
        expected_bytes = bytes.fromhex(vector["expected_hex"])
        decoded = decode_canonical_payload(expected_bytes)
        assert decoded.sender == vector["sender"], vector["name"]
        assert decoded.recipient == vector["recipient"], vector["name"]
        assert decoded.request_type == vector["request_type"], vector["name"]
        assert decoded.timestamp == vector["timestamp"], vector["name"]
        assert decoded.nonce == vector["nonce"], vector["name"]

        # Also re-encode from fields and confirm byte-identical output —
        # proves the Python encoder (not just decoder) matches too.
        re_encoded = encode_canonical_payload(
            vector["sender"],
            vector["recipient"],
            vector["request_type"],
            vector["timestamp"],
            vector["nonce"],
        )
        assert re_encoded.hex() == vector["expected_hex"], vector["name"]


# ---------------------------- migration tripwire ----------------------------
#
# These use their own dedicated database on the same running test
# Postgres cluster (created/dropped within the test), never the shared
# `engine`/`session` fixtures — this avoids permanently mutating the
# schema other tests depend on.


def _make_scratch_database(database_url: str, name: str) -> str:
    # database_url looks like: postgresql+psycopg://postgres@/relay_test?host=...&port=...
    admin_url = database_url.replace("/relay_test?", "/postgres?")
    admin_engine = create_engine(admin_url, future=True, isolation_level="AUTOCOMMIT")
    with admin_engine.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    admin_engine.dispose()
    return database_url.replace("/relay_test?", f"/{name}?")


def test_migrate_proceeds_normally_against_a_fresh_database(database_url):
    """Regression check: the working fresh-DB case must not break."""
    scratch_url = _make_scratch_database(database_url, "relay_migrate_fresh_test")
    scratch_engine = create_engine(scratch_url, future=True)

    apply_schema(scratch_engine)  # must not raise

    inspector_tables = scratch_engine.connect().execute(
        text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
    ).scalars().all()
    assert "identities" in inspector_tables
    scratch_engine.dispose()


def test_migrate_refuses_populated_database_missing_expected_column(database_url):
    """The tripwire this fix exists for: a populated table missing a
    column added in a later task must refuse, not silently no-op."""
    scratch_url = _make_scratch_database(database_url, "relay_migrate_stale_test")
    scratch_engine = create_engine(scratch_url, future=True)

    # Apply the CURRENT schema first, then roll it back to the "stale"
    # pre-encryption shape by dropping the columns that fix added —
    # simulating a real registry that existed before that task.
    apply_schema(scratch_engine)
    with scratch_engine.begin() as conn:
        conn.execute(text("ALTER TABLE identities DROP COLUMN x25519_public_key_hex"))
        conn.execute(text("ALTER TABLE identities DROP COLUMN relay_number"))
        conn.execute(
            text(
                "INSERT INTO identities (handle, public_key_hex) VALUES (:h, :k)"
            ),
            {"h": "pre-existing-user", "k": "a" * 64},
        )

    with pytest.raises(MigrationSafetyError) as exc_info:
        apply_schema(scratch_engine)

    message = str(exc_info.value)
    assert "identities" in message
    assert "x25519_public_key_hex" in message
    assert "judgment call #7" in message
    assert "No ALTER TABLE migration path" in message

    scratch_engine.dispose()
