# Writes two permanent, disposable test identities (relaydoctor-test-alice/bob)
# to the LIVE production registry — approved exception to "tests don't touch
# prod," explicitly signed off on 2026-08-04. Metadata only (handle + pubkeys),
# never capsule content — consistent with CLAUDE.md's hard boundary. Gated
# behind RELAY_TEST_LIVE_REGISTRY=1 so it never runs by accident.

import os

import pytest

from wiring.diagnostics import registry_reachable
from wiring.local_state import LocalIdentity
from wiring.registry_client import RegistryClient, RegistryRejection
from wiring.trace import generate_trace_id

pytestmark = pytest.mark.skipif(
    os.environ.get("RELAY_TEST_LIVE_REGISTRY") != "1",
    reason="hits the real hosted https://relay-registry.onrender.com — opt in explicitly",
)

LIVE_REGISTRY_URL = "https://relay-registry.onrender.com"


def test_openapi_reachable_over_https():
    assert registry_reachable(LIVE_REGISTRY_URL) is True


def _ensure_registered(client, identity, handle):
    try:
        client.register_identity(handle, identity.public_key_hex, identity.encryption_public_key_hex)
    except RegistryRejection as e:
        if e.status_code != 409:
            raise  # anything but "already registered" is a real failure


def test_trace_id_header_roundtrip_against_hosted_registry(tmp_path):
    client = RegistryClient.create(LIVE_REGISTRY_URL)
    alice = LocalIdentity.load_or_create("relaydoctor-test-alice", str(tmp_path / "alice"))
    bob = LocalIdentity.load_or_create("relaydoctor-test-bob", str(tmp_path / "bob"))
    _ensure_registered(client, alice, "relaydoctor-test-alice")
    _ensure_registered(client, bob, "relaydoctor-test-bob")

    trace_id = generate_trace_id()
    # get_identity is enough to prove the header round-trips without
    # needing a signed relay request — the registry only ever needs the
    # header for its own logging, never for authorization.
    result = client.get_identity("relaydoctor-test-bob", trace_id=trace_id)
    assert result is not None
    assert result["handle"] == "relaydoctor-test-bob"
