# Route-level HTTP test for POST /grants and POST /grants/revoke.
#
# Proves the fix for the gap flagged this task: these endpoints
# previously accepted grantor/grant_id as unauthenticated claims
# (grant_service.create_grant/revoke_grant took them directly, no
# signature check), contradicting PRD.md §5 R2 ("MUST NEVER resolve
# grants or approvals based on a claimed handle string alone"). Now:
# a request with a valid handle but no/wrong signature must be
# rejected with zero state mutation, and a real signed request must
# succeed and be visible to a direct DB read — same acceptance
# criterion shape as R2's own text.

import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from registry.app import app
from registry.db import get_session
from registry.models.tables import grants
from registry.services import identity_service
from registry.services.grant_payload import encode_grant_create_payload, encode_grant_revoke_payload

VALID_NONCE_A = "0123456789abcdef0123456789abcdef"
VALID_NONCE_B = "fedcba9876543210fedcba9876543210"


def make_identity(session, handle: str):
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    x25519_public_key_hex = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    identity_service.register_identity(session, handle, public_key_hex, x25519_public_key_hex)
    return private_key


def client_for(session):
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def test_create_grant_with_valid_signature_succeeds_and_is_stored(session):
    rohan_key = make_identity(session, "rohan")
    make_identity(session, "vivek")
    session.commit()
    now_ts = int(time.time())

    canonical = encode_grant_create_payload(
        "rohan", "vivek", "standing", ["c1", "c2"], None, now_ts, VALID_NONCE_A
    )
    signature_hex = rohan_key.sign(canonical).hex()

    client = client_for(session)
    try:
        response = client.post(
            "/grants",
            json={
                "grantor": "rohan",
                "grantee": "vivek",
                "grant_type": "standing",
                "scope_capsule_ids": ["c1", "c2"],
                "timestamp": now_ts,
                "nonce": VALID_NONCE_A,
                "signature_hex": signature_hex,
            },
        )
        assert response.status_code == 201, response.text
        grant_id = response.json()["id"]

        row = session.execute(select(grants).where(grants.c.id == grant_id)).mappings().first()
        assert row["grantor"] == "rohan"
        assert row["grantee"] == "vivek"
        assert row["scope_capsule_ids"] == ["c1", "c2"]
    finally:
        app.dependency_overrides.clear()


def test_create_grant_with_wrong_signature_rejected_no_state_mutation(session):
    make_identity(session, "rohan")
    make_identity(session, "vivek")
    attacker_key = Ed25519PrivateKey.generate()  # NOT rohan's real key
    session.commit()
    now_ts = int(time.time())

    canonical = encode_grant_create_payload(
        "rohan", "vivek", "standing", ["c1"], None, now_ts, VALID_NONCE_A
    )
    forged_signature_hex = attacker_key.sign(canonical).hex()

    client = client_for(session)
    try:
        response = client.post(
            "/grants",
            json={
                "grantor": "rohan",
                "grantee": "vivek",
                "grant_type": "standing",
                "scope_capsule_ids": ["c1"],
                "timestamp": now_ts,
                "nonce": VALID_NONCE_A,
                "signature_hex": forged_signature_hex,
            },
        )
        assert response.status_code == 401, response.text
        assert response.json()["detail"]["outcome"] == "invalid_signature"

        rows = session.execute(select(grants).where(grants.c.grantor == "rohan")).mappings().all()
        assert rows == [], "no grant should have been created from a forged signature"
    finally:
        app.dependency_overrides.clear()


def test_create_grant_signature_does_not_cover_swapped_capsule_ids(session):
    # Confirms the signature binds scope_capsule_ids, not just the
    # envelope: a valid signature for one capsule list can't be replayed
    # with a different capsule list swapped in.
    rohan_key = make_identity(session, "rohan")
    make_identity(session, "vivek")
    session.commit()
    now_ts = int(time.time())

    canonical = encode_grant_create_payload(
        "rohan", "vivek", "standing", ["c1"], None, now_ts, VALID_NONCE_A
    )
    signature_hex = rohan_key.sign(canonical).hex()

    client = client_for(session)
    try:
        response = client.post(
            "/grants",
            json={
                "grantor": "rohan",
                "grantee": "vivek",
                "grant_type": "standing",
                "scope_capsule_ids": ["c1", "sensitive-doc"],  # swapped in, not signed
                "timestamp": now_ts,
                "nonce": VALID_NONCE_A,
                "signature_hex": signature_hex,
            },
        )
        assert response.status_code == 401
        assert response.json()["detail"]["outcome"] == "invalid_signature"
    finally:
        app.dependency_overrides.clear()


def test_revoke_grant_requires_signature_from_actual_grantor(session):
    rohan_key = make_identity(session, "rohan")
    make_identity(session, "vivek")
    attacker_key = Ed25519PrivateKey.generate()
    session.commit()
    now_ts = int(time.time())

    create_canonical = encode_grant_create_payload(
        "rohan", "vivek", "standing", ["c1"], None, now_ts, VALID_NONCE_A
    )
    create_signature_hex = rohan_key.sign(create_canonical).hex()

    client = client_for(session)
    try:
        create_response = client.post(
            "/grants",
            json={
                "grantor": "rohan",
                "grantee": "vivek",
                "grant_type": "standing",
                "scope_capsule_ids": ["c1"],
                "timestamp": now_ts,
                "nonce": VALID_NONCE_A,
                "signature_hex": create_signature_hex,
            },
        )
        grant_id = create_response.json()["id"]

        # Attacker tries to revoke rohan's grant with their own key.
        revoke_canonical = encode_grant_revoke_payload(grant_id, now_ts, VALID_NONCE_B)
        forged_revoke_signature_hex = attacker_key.sign(revoke_canonical).hex()

        revoke_response = client.post(
            "/grants/revoke",
            json={
                "grant_id": grant_id,
                "timestamp": now_ts,
                "nonce": VALID_NONCE_B,
                "signature_hex": forged_revoke_signature_hex,
            },
        )
        assert revoke_response.status_code == 401
        assert revoke_response.json()["detail"]["outcome"] == "invalid_signature"

        row = session.execute(select(grants).where(grants.c.id == grant_id)).mappings().first()
        assert row["revoked_at"] is None, "grant must not be revoked by a forged signature"

        # Real grantor's signature succeeds.
        real_revoke_signature_hex = rohan_key.sign(revoke_canonical).hex()
        revoke_response = client.post(
            "/grants/revoke",
            json={
                "grant_id": grant_id,
                "timestamp": now_ts,
                "nonce": VALID_NONCE_B,
                "signature_hex": real_revoke_signature_hex,
            },
        )
        assert revoke_response.status_code == 200, revoke_response.text

        row = session.execute(select(grants).where(grants.c.id == grant_id)).mappings().first()
        assert row["revoked_at"] is not None
    finally:
        app.dependency_overrides.clear()
