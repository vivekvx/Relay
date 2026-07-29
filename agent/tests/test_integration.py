# Integration tests: real resolver, real identity (relay_identity PyO3
# bridge — the actual Rust crypto, not a stub), real approval (mocked
# terminal input only, per the task's explicit allowance), and a real
# registry (FastAPI + ephemeral Postgres via conftest.py's
# registry_client fixture) — proving the actual end-to-end wiring in
# agent/wiring/flows.py, not just that each piece works alone (already
# proven by resolver/approval/identity/registry's own test suites).

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from resolver.rate_limiter import RateLimiter
from resolver.resolver import resolve_scope
from resolver.types import Capsule, Grant, GrantType, SenderIdentity

from wiring.flows import PendingResponseRegistry, ask, grant, poll_once, revoke
from wiring.local_state import LocalIdentity
from wiring.registry_client import RegistryRejection


def now() -> datetime:
    return datetime.now(timezone.utc)  # real wall clock; registry enforces a real freshness window


def make_identity(handle: str, tmp_path, registry_client) -> LocalIdentity:
    identity = LocalIdentity.load_or_create(handle, str(tmp_path / handle / "keys"))
    registry_client.register_identity(handle, identity.public_key_hex, identity.encryption_public_key_hex)
    return identity


def write_capsule(capsule_dir, capsule_id: str, shareable_with: str, tags: str, content: str) -> None:
    capsule_dir.mkdir(parents=True, exist_ok=True)
    (capsule_dir / f"{capsule_id}.md").write_text(
        f"id: {capsule_id}\nshareable: true\nshareable_with: {shareable_with}\ntags: {tags}\n\n{content}",
        encoding="utf-8",
    )


def deliver(sender_identity, recipient_identity, registry_client, recipient_capsule_dir, rate_limiter, response_registry, input_fn, output_fn=lambda l: None):
    """Runs one poll cycle on the recipient (processes any inbound ask),
    then one poll cycle on the sender (delivers any inbound response)."""
    poll_once(recipient_identity, registry_client, str(recipient_capsule_dir), rate_limiter, PendingResponseRegistry(), input_fn=input_fn, output_fn=output_fn)
    poll_once(sender_identity, registry_client, str(recipient_capsule_dir), rate_limiter, response_registry, input_fn=input_fn, output_fn=output_fn)


def grants_for(registry_client, grantee: str, grantor: str) -> list[Grant]:
    rows = registry_client.list_grants(grantee=grantee)
    return [
        Grant(
            type=GrantType(row["grant_type"]),
            grantor=row["grantor"],
            grantee=row["grantee"],
            capsule_ids=frozenset(row["scope_capsule_ids"]),
            revoked=row["revoked_at"] is not None,
            expires_at=None,
        )
        for row in rows
        if row["grantor"] == grantor
    ]


# ---------------------------------------------------------------------
# Standing-grant `relay ask` end to end
# ---------------------------------------------------------------------


def test_standing_grant_ask_end_to_end(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(capsule_dir, "backoff", "vivek", "webhook,retry", "Use exponential backoff with jitter.")

    # rohan creates a standing grant covering vivek for this capsule.
    grant(rohan, registry_client, grantee="vivek", grant_type="standing", scope_capsule_ids=["backoff"], now_fn=now)

    response_registry = PendingResponseRegistry()
    result = ask(vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, wait_attempts=1, now_fn=now)
    assert result["status"] == "pending"  # rohan hasn't polled yet

    def fail_input(prompt):
        raise AssertionError("standing-grant branch must never prompt a human")

    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=fail_input)

    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "approved_whole"
    assert answered["cited_capsule_ids"] == ["backoff"]
    assert "exponential backoff with jitter" in answered["answer"]


# ---------------------------------------------------------------------
# Ad hoc `relay ask` end to end: approve-whole
# ---------------------------------------------------------------------


def test_ad_hoc_ask_approve_whole_end_to_end(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(capsule_dir, "backoff", "vivek", "webhook,retry", "Use exponential backoff with jitter for webhook retries.")

    response_registry = PendingResponseRegistry()
    result = ask(vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, wait_attempts=1, now_fn=now)

    answers = iter(["w", "1", "n"])  # approve-whole, doc 1, decline grant promotion
    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers))

    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "approved_whole"
    assert answered["cited_capsule_ids"] == ["backoff"]
    assert "exponential backoff" in answered["answer"]


# ---------------------------------------------------------------------
# Ad hoc `relay ask` with mocked deny — no capsule content anywhere
# ---------------------------------------------------------------------


def test_ad_hoc_ask_deny_no_capsule_content_anywhere(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    secret_content = "SENSITIVE-INCIDENT-DETAIL-do-not-share"
    write_capsule(capsule_dir, "incident", "vivek", "incident", secret_content)

    response_registry = PendingResponseRegistry()
    result = ask(vivek, registry_client, "rohan", "what happened in the incident?", response_registry, wait_attempts=1, now_fn=now)

    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: "d")

    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "denied"
    assert answered["cited_capsule_ids"] == []
    assert secret_content not in answered["answer"]
    # Both items (ask + ask_response) were already delivered above via
    # poll_once, so nothing capsule-shaped is left sitting in the queue.
    assert registry_client.fetch_pending("vivek") == []


# ---------------------------------------------------------------------
# Ad hoc `relay ask` with mocked manual-answer — no capsule content
# ---------------------------------------------------------------------


def test_ad_hoc_ask_manual_answer_no_capsule_content(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    secret_content = "full-doc-content-that-must-not-leak"
    write_capsule(capsule_dir, "doc", "vivek", "topic", secret_content)

    response_registry = PendingResponseRegistry()
    result = ask(vivek, registry_client, "rohan", "tell me about topic", response_registry, wait_attempts=1, now_fn=now)

    answers = iter(["m", "We use exponential backoff, see the wiki."])
    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers))

    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "manual_answer"
    assert answered["answer"] == "We use exponential backoff, see the wiki."
    assert answered["cited_capsule_ids"] == []
    assert secret_content not in answered["answer"]


# ---------------------------------------------------------------------
# relay grant / relay revoke change resolver-observed state
# ---------------------------------------------------------------------


def test_relay_grant_and_revoke_change_resolver_observed_state(tmp_path, registry_client):
    make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsules_by_id = {"c1": Capsule(id="c1", shareable=True, shareable_with=frozenset({"vivek"}), tags=frozenset(), content="x")}

    grant_id = grant(rohan, registry_client, grantee="vivek", grant_type="standing", scope_capsule_ids=["c1"], now_fn=now)

    permitted = resolve_scope(SenderIdentity("vivek"), grants_for(registry_client, "vivek", "rohan"), capsules_by_id, now())
    assert permitted == frozenset({"c1"})

    revoke(rohan, registry_client, grant_id, now_fn=now)

    permitted_after_revoke = resolve_scope(
        SenderIdentity("vivek"), grants_for(registry_client, "vivek", "rohan"), capsules_by_id, now()
    )
    assert permitted_after_revoke == frozenset()


def test_relay_revoke_by_non_owner_is_rejected(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    grant_id = grant(rohan, registry_client, grantee="vivek", grant_type="standing", scope_capsule_ids=["c1"], now_fn=now)

    with pytest.raises(RegistryRejection) as excinfo:
        revoke(vivek, registry_client, grant_id, now_fn=now)  # vivek is not the grantor
    assert excinfo.value.outcome == "invalid_signature"


# ---------------------------------------------------------------------
# Tampered-in-transit message: rejected at identity verification,
# never reaches the relay queue at all (so it can never reach resolver).
# ---------------------------------------------------------------------


def test_tampered_message_rejected_at_registry_never_reaches_queue(tmp_path, registry_client):
    import relay_identity as ri

    vivek = make_identity("vivek", tmp_path, registry_client)
    make_identity("rohan", tmp_path, registry_client)

    payload = ri.RequestPayload("vivek", "rohan", "ask", int(now().timestamp()), "0123456789abcdef0123456789abcdef")
    canonical_bytes, signature_bytes = ri.sign_payload(vivek.private_key, payload)

    # Flip the low bit of the timestamp field (offset 32: 4+5 sender +
    # 4+5 recipient + 4+3 request_type = 25, +7 into the 8-byte
    # timestamp). This shifts the timestamp by ~1 second — still well
    # inside the freshness window, sender/recipient/request_type/nonce
    # all still decode to the exact same, still-registered values — so
    # every other check (unknown_sender, malformed_payload,
    # expired_timestamp) passes and ONLY the signature check can fail.
    # Isolates "signature verification specifically rejects this" from
    # every other, also-legitimate rejection reason this test isn't about.
    tampered = bytearray(canonical_bytes)
    tampered[32] ^= 0x01

    with pytest.raises(RegistryRejection) as excinfo:
        registry_client.submit_relay(bytes(tampered).hex(), signature_bytes.hex())
    assert excinfo.value.outcome == "invalid_signature"

    # Fails closed at the identity-verification layer specifically: the
    # item was never enqueued at all, so it is structurally impossible
    # for resolve_scope/search_candidates to ever see it.
    assert registry_client.fetch_pending("rohan") == []
