# Route-level HTTP test for the new per-IP rate limit on GET
# /identities/{handle} and GET /identities/by-relay-number/{relay_number}
# — proves the fix for the unauthenticated-enumeration finding: normal,
# low-volume lookup usage is unaffected, but a sustained run of lookups
# past DEFAULT_LOOKUP_LIMIT_PER_HOUR gets rejected with 429.

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from registry.app import app
from registry.db import get_session
from registry.services import identity_service
from registry.services.identity_lookup_rate_limit_service import DEFAULT_LOOKUP_LIMIT_PER_HOUR


def make_identity(session, handle: str) -> str:
    public_key_hex = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    x25519_public_key_hex = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    relay_number = identity_service.register_identity(session, handle, public_key_hex, x25519_public_key_hex)
    session.commit()
    return relay_number


def client_for(session) -> TestClient:
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def test_normal_single_lookup_usage_is_never_affected(session):
    make_identity(session, "rohan")
    client = client_for(session)

    # A handful of lookups, like a real ask()/whoami/contacts flow would
    # make — nowhere near the 60/hour limit.
    for _ in range(5):
        response = client.get("/identities/rohan")
        assert response.status_code == 200
        assert response.json()["handle"] == "rohan"


def test_handle_lookup_rate_limit_fires_past_the_default(session):
    make_identity(session, "rohan")
    client = client_for(session)

    for i in range(DEFAULT_LOOKUP_LIMIT_PER_HOUR):
        response = client.get("/identities/rohan")
        assert response.status_code == 200, f"request {i} unexpectedly rejected"

    over_limit = client.get("/identities/rohan")
    assert over_limit.status_code == 429
    assert over_limit.json()["detail"]["outcome"] == "rate_limited"


def test_relay_number_lookup_rate_limit_fires_past_the_default(session):
    relay_number = make_identity(session, "rohan")
    client = client_for(session)

    for i in range(DEFAULT_LOOKUP_LIMIT_PER_HOUR):
        response = client.get(f"/identities/by-relay-number/{relay_number}")
        assert response.status_code == 200, f"request {i} unexpectedly rejected"

    over_limit = client.get(f"/identities/by-relay-number/{relay_number}")
    assert over_limit.status_code == 429
    assert over_limit.json()["detail"]["outcome"] == "rate_limited"


def test_handle_and_relay_number_lookups_share_the_same_per_ip_counter(session):
    # Both endpoints exist specifically because they're two ways to
    # reach the same enumerable data — the rate limit must bound them
    # together per source IP, not give an attacker double the budget by
    # alternating endpoints.
    relay_number = make_identity(session, "rohan")
    client = client_for(session)

    half = DEFAULT_LOOKUP_LIMIT_PER_HOUR // 2
    for _ in range(half):
        assert client.get("/identities/rohan").status_code == 200
    for _ in range(DEFAULT_LOOKUP_LIMIT_PER_HOUR - half):
        assert client.get(f"/identities/by-relay-number/{relay_number}").status_code == 200

    assert client.get("/identities/rohan").status_code == 429


def test_rejected_lookup_still_returns_404_shape_for_unknown_handle_under_the_limit(session):
    # Sanity check the two failure modes (unknown handle vs. rate
    # limited) stay distinguishable — a 429 must never masquerade as a
    # 404 or vice versa.
    client = client_for(session)
    response = client.get("/identities/nobody-registered")
    assert response.status_code == 404
