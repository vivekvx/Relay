# Integration tests: real resolver, real identity (relay_identity PyO3
# bridge — the actual Rust crypto, not a stub), real approval (mocked
# terminal input only, per the task's explicit allowance), and a real
# registry (FastAPI + ephemeral Postgres via conftest.py's
# registry_client fixture) — proving the actual end-to-end wiring in
# agent/wiring/flows.py, not just that each piece works alone (already
# proven by resolver/approval/identity/registry's own test suites).

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from resolver.rate_limiter import RateLimiter
from resolver.resolver import resolve_scope
from resolver.types import Capsule, Grant, GrantType, SenderIdentity

from wiring.contacts import ContactsStore, resolve_recipient
from wiring.disclosure_log import DisclosureLog
from wiring.flows import PendingResponseRegistry, ask, grant, poll_once, resolve_pending_approval, revoke
from wiring.local_state import LocalIdentity
from wiring.pending_approvals import PendingApprovalStore
from wiring.registry_client import RegistryRejection
from wiring.threads import ThreadStore


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


def ephemeral_thread_store(tmp_path, name: str = "threads") -> ThreadStore:
    """A fresh ThreadStore backed by a tmp_path file — used by tests that
    don't care about thread continuation; thread tests below construct
    their own named ThreadStore explicitly so it can be reused/inspected
    across multiple ask()/deliver() calls within one test."""
    return ThreadStore(str(tmp_path / f"{name}.json"))


def ephemeral_disclosure_log(tmp_path, name: str = "disclosure_log") -> DisclosureLog:
    """Same pattern as ephemeral_thread_store, for DisclosureLog."""
    return DisclosureLog(str(tmp_path / f"{name}.json"))


def ephemeral_pending_approval_store(tmp_path, name: str = "pending_approvals") -> PendingApprovalStore:
    """Same pattern as ephemeral_thread_store, for PendingApprovalStore."""
    return PendingApprovalStore(str(tmp_path / f"{name}.json"))


def deliver(
    sender_identity, recipient_identity, registry_client, recipient_capsule_dir, rate_limiter, response_registry,
    input_fn, output_fn=lambda l: None, recipient_thread_store=None, sender_thread_store=None,
    recipient_disclosure_log=None,
):
    """Runs one poll cycle on the recipient (processes any inbound ask),
    then one poll cycle on the sender (delivers any inbound response).
    thread_store/disclosure_log params default to a disposable one-off
    store when the caller doesn't need to inspect/reuse state across
    turns."""
    import tempfile

    recipient_thread_store = recipient_thread_store or ThreadStore(tempfile.mktemp(suffix=".json"))
    sender_thread_store = sender_thread_store or ThreadStore(tempfile.mktemp(suffix=".json"))
    recipient_disclosure_log = recipient_disclosure_log or DisclosureLog(tempfile.mktemp(suffix=".json"))
    poll_once(
        recipient_identity, registry_client, str(recipient_capsule_dir), rate_limiter, PendingResponseRegistry(),
        recipient_thread_store, recipient_disclosure_log, input_fn=input_fn, output_fn=output_fn,
    )
    poll_once(
        sender_identity, registry_client, str(recipient_capsule_dir), rate_limiter, response_registry,
        sender_thread_store, DisclosureLog(tempfile.mktemp(suffix=".json")), input_fn=input_fn, output_fn=output_fn,
    )


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
    thread_store = ephemeral_thread_store(tmp_path)
    result = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
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
    thread_store = ephemeral_thread_store(tmp_path)
    result = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )

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
    thread_store = ephemeral_thread_store(tmp_path)
    result = ask(
        vivek, registry_client, "rohan", "what happened in the incident?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )

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
    thread_store = ephemeral_thread_store(tmp_path)
    result = ask(
        vivek, registry_client, "rohan", "tell me about topic", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )

    answers = iter(["m", "We use exponential backoff, see the wiki."])
    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers))

    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "manual_answer"
    assert answered["answer"] == "We use exponential backoff, see the wiki."
    assert answered["cited_capsule_ids"] == []
    assert secret_content not in answered["answer"]


# ---------------------------------------------------------------------
# Contacts + relay numbers: ask-by-contact-name resolves through the
# real registry, identically to a raw handle
# ---------------------------------------------------------------------


def test_ask_by_contact_name_resolves_to_same_recipient_as_raw_handle(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    rohan_identity = registry_client.get_identity("rohan")
    rohan_relay_number = rohan_identity["relay_number"]
    assert rohan_relay_number != "rohan"  # opaque — never just the handle

    contacts = ContactsStore(str(tmp_path / "vivek_contacts.json"))
    contacts.add("my-friend", rohan_relay_number)
    resolved_handle = resolve_recipient(contacts, registry_client, "my-friend")
    assert resolved_handle == "rohan"

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(capsule_dir, "backoff", "vivek", "webhook,retry", "Use exponential backoff with jitter.")

    grant(rohan, registry_client, grantee="vivek", grant_type="standing", scope_capsule_ids=["backoff"], now_fn=now)

    response_registry = PendingResponseRegistry()
    result = ask(
        vivek, registry_client, resolved_handle, "how do you handle webhook retries?", response_registry,
        ephemeral_thread_store(tmp_path), wait_attempts=1, now_fn=now,
    )
    assert result["status"] == "pending"

    deliver(vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: "unused")
    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "approved_whole"
    assert answered["cited_capsule_ids"] == ["backoff"]


def test_resolve_recipient_raw_handle_still_works_unchanged(tmp_path, registry_client):
    make_identity("vivek", tmp_path, registry_client)
    make_identity("rohan", tmp_path, registry_client)
    contacts = ContactsStore(str(tmp_path / "empty_contacts.json"))  # no saved contacts at all
    assert resolve_recipient(contacts, registry_client, "rohan") == "rohan"


# ---------------------------------------------------------------------
# Multi-turn `relay ask` — conversation threading (spec CASE A/B)
# ---------------------------------------------------------------------


def test_same_scope_followup_skips_approval(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")

    result1 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    thread_id = result1["thread_id"]

    answers = iter(["w", "1", "n"])  # approve-whole, doc 1, decline grant promotion
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers),
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered1 = response_registry.pop(result1["nonce"])
    assert answered1["outcome"] == "approved_whole"
    assert answered1["cited_capsule_ids"] == ["backoff"]

    # Follow-up in the SAME thread, same capsule as the only candidate —
    # must NOT re-prompt (CASE A).
    result2 = ask(
        vivek, registry_client, "rohan", "why backoff specifically for retries?", response_registry, thread_store,
        thread_id=thread_id, wait_attempts=1, now_fn=now,
    )

    def fail_input(prompt):
        raise AssertionError("same-scope follow-up must never re-prompt for approval")

    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=fail_input,
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered2 = response_registry.pop(result2["nonce"])
    assert answered2["outcome"] == "approved_whole"
    assert answered2["cited_capsule_ids"] == ["backoff"]
    assert answered2["thread_id"] == thread_id


def test_new_scope_followup_prompts_only_for_new_capsule(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )
    write_capsule(
        capsule_dir, "scaling", "vivek", "webhook,scale",
        "Scale webhook workers horizontally behind a queue.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")

    result1 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    thread_id = result1["thread_id"]

    answers1 = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers1),
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered1 = response_registry.pop(result1["nonce"])
    assert answered1["cited_capsule_ids"] == ["backoff"]

    # Follow-up whose keywords hit BOTH capsules — "backoff" is already
    # approved in this thread, "scaling" is not (CASE B): the resolver
    # must only ask about "scaling", and the final answer should still
    # include the already-approved "backoff" content alongside it.
    result2 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook load at scale?", response_registry, thread_store,
        thread_id=thread_id, wait_attempts=1, now_fn=now,
    )
    answers2 = iter(["w", "1", "n"])  # approve-whole; "1" is the only (new) candidate offered
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers2),
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered2 = response_registry.pop(result2["nonce"])
    assert answered2["outcome"] == "approved_whole"
    assert set(answered2["cited_capsule_ids"]) == {"backoff", "scaling"}
    assert rohan_threads.get(thread_id).approved_capsule_ids == ["backoff", "scaling"]


def test_fresh_thread_does_not_inherit_prior_threads_approved_scope(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")

    result1 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    answers = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=lambda p: next(answers),
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    response_registry.pop(result1["nonce"])

    # A BRAND-NEW thread (no --thread), same two participants, same
    # question that was already approved in the prior thread — this
    # must still go through live approval, never auto-continue.
    result2 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    assert result2["thread_id"] != result1["thread_id"]

    def fail_input(prompt):
        raise AssertionError("a fresh thread must never inherit another thread's approved scope")

    with pytest.raises(AssertionError):
        deliver(
            vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry, input_fn=fail_input,
            recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
        )


def test_rate_limit_still_applies_per_message_within_a_thread(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")
    shared_rate_limiter = RateLimiter(default_limit=1)  # only 1 message/hour allowed

    result1 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    thread_id = result1["thread_id"]
    answers = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, shared_rate_limiter, response_registry,
        input_fn=lambda p: next(answers), recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered1 = response_registry.pop(result1["nonce"])
    assert answered1["outcome"] == "approved_whole"

    # Second message, same thread, same rate limiter already at its
    # limit — must be denied for rate limiting, threading changes nothing.
    result2 = ask(
        vivek, registry_client, "rohan", "why backoff specifically?", response_registry, thread_store,
        thread_id=thread_id, wait_attempts=1, now_fn=now,
    )

    def fail_input(prompt):
        raise AssertionError("a rate-limited message must never reach the approval/resolver step")

    deliver(
        vivek, rohan, registry_client, capsule_dir, shared_rate_limiter, response_registry, input_fn=fail_input,
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered2 = response_registry.pop(result2["nonce"])
    assert answered2["outcome"] == "denied"
    assert "rate limit" in answered2["answer"]


def test_expired_thread_does_not_auto_continue(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")
    rate_limiter = RateLimiter()

    result1 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    thread_id = result1["thread_id"]

    answers = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, rate_limiter, response_registry, input_fn=lambda p: next(answers),
        recipient_thread_store=rohan_threads, sender_thread_store=thread_store,
    )
    answered1 = response_registry.pop(result1["nonce"])
    assert answered1["outcome"] == "approved_whole"

    # Simulates 25h of inactivity since the last message in this thread —
    # done by backdating the recipient's own local record directly rather
    # than faking a signed request's timestamp (which the registry's own
    # freshness check would reject as outside its validity window; that
    # check is orthogonal to, and independent of, this conversation-level
    # expiry). Real, current wall-clock timestamps are used for the
    # second wire round trip below.
    records = rohan_threads._load()
    records[thread_id].last_activity_at = (now() - timedelta(hours=25)).isoformat()
    rohan_threads._save(records)

    # Same thread_id, same question — but this thread's accumulated
    # approval is now past its 24h inactivity expiry, so it must NOT be
    # trusted; a fresh prompt is required (safe default, never a silent
    # auto-grant past the conversation's own expiry).
    result2 = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        thread_id=thread_id, wait_attempts=1, now_fn=now,
    )
    assert result2["thread_id"] == thread_id

    def fail_input(prompt):
        raise AssertionError("an inactivity-expired thread must not auto-continue")

    with pytest.raises(AssertionError):
        poll_once(
            rohan, registry_client, str(capsule_dir), rate_limiter, PendingResponseRegistry(), rohan_threads,
            ephemeral_disclosure_log(tmp_path, "rohan_disclosure"), input_fn=fail_input, now_fn=now,
        )


# ---------------------------------------------------------------------
# Structured pre-ask fields (reason/urgency) — display only, never
# affect resolution
# ---------------------------------------------------------------------


def test_reason_and_urgency_shown_but_dont_change_resolved_capsules(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    captured_prompts: list[str] = []

    result = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry,
        ephemeral_thread_store(tmp_path), reason="debugging a similar retry issue in my own project",
        urgency="not time-sensitive", wait_attempts=1, now_fn=now,
    )
    answers = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry,
        input_fn=lambda p: next(answers), output_fn=captured_prompts.append,
    )
    answered_with_reason = response_registry.pop(result["nonce"])
    assert answered_with_reason["cited_capsule_ids"] == ["backoff"]

    # The rendered prompt shows the structured fields, clearly labeled.
    prompt_text = "\n".join(captured_prompts)
    assert 'Asking: "how do you handle webhook retries?"' in prompt_text
    assert 'Reason: "debugging a similar retry issue in my own project"' in prompt_text
    assert "Urgency: not time-sensitive" in prompt_text

    # Omitted reason/urgency render their documented defaults — proven
    # separately (identical resolved candidates regardless of reason/
    # urgency is proven at the resolver level:
    # resolver/tests/test_resolver.py's TestStructuredFieldsDontAffectResolution,
    # since search_candidates never receives these fields as arguments
    # at all, by construction).
    captured_prompts.clear()
    result_no_metadata = ask(
        vivek, registry_client, "rohan", "why exponential backoff for webhook retries?", response_registry,
        ephemeral_thread_store(tmp_path, "no_metadata"), wait_attempts=1, now_fn=now,
    )
    answers_no_metadata = iter(["w", "1", "n"])
    deliver(
        vivek, rohan, registry_client, capsule_dir, RateLimiter(), response_registry,
        input_fn=lambda p: next(answers_no_metadata), output_fn=captured_prompts.append,
    )
    answered_no_metadata = response_registry.pop(result_no_metadata["nonce"])
    assert answered_no_metadata["cited_capsule_ids"] == answered_with_reason["cited_capsule_ids"]
    prompt_text_no_metadata = "\n".join(captured_prompts)
    assert "Reason: (no reason given)" in prompt_text_no_metadata
    assert "Urgency: not time-sensitive" in prompt_text_no_metadata


# ---------------------------------------------------------------------
# Anti-enumeration guard — advisory line in the approval prompt
# ---------------------------------------------------------------------


def test_enumeration_warning_normal_use_never_fires_then_fires_on_broad_pattern(tmp_path, registry_client):
    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(capsule_dir, "c1", "vivek", "topic1", "Content about topic one specifically.")
    write_capsule(capsule_dir, "c2", "vivek", "topic2", "Content about topic two specifically.")
    write_capsule(capsule_dir, "c3", "vivek", "topic3", "Content about topic three specifically.")

    response_registry = PendingResponseRegistry()
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")
    rohan_disclosure = ephemeral_disclosure_log(tmp_path, "rohan_disclosure")
    captured: list[str] = []

    def ask_and_approve(question: str) -> None:
        result = ask(
            vivek, registry_client, "rohan", question, response_registry, ephemeral_thread_store(tmp_path, "v"),
            wait_attempts=1, now_fn=now,
        )
        answers = iter(["w", "1", "n"])
        poll_once(
            rohan, registry_client, str(capsule_dir), RateLimiter(), PendingResponseRegistry(), rohan_threads,
            rohan_disclosure, input_fn=lambda p: next(answers), output_fn=captured.append, now_fn=now,
        )
        poll_once(
            vivek, registry_client, str(capsule_dir), RateLimiter(), response_registry,
            ephemeral_thread_store(tmp_path, "v"), ephemeral_disclosure_log(tmp_path, "v_disc"),
            input_fn=lambda p: "unused", now_fn=now,
        )
        response_registry.pop(result["nonce"])

    # Turn 1: normal, low-volume use — 0 of 3 capsules seen so far (33%
    # after this one, still under 40%... actually checked BEFORE this
    # decision, so 0/3 here) — must never fire.
    ask_and_approve("tell me about topic one specifically")
    assert not any("Heads up" in line for line in captured)

    # Turn 2: still normal — 1 of 3 seen so far (33%, under 40%) — must
    # still never fire.
    captured.clear()
    ask_and_approve("tell me about topic two specifically")
    assert not any("Heads up" in line for line in captured)

    # Turn 3: now 2 of 3 capsules already seen (66% > 40% default
    # threshold) — deliberate-enumeration pattern, must fire with the
    # exact numbers that triggered it.
    captured.clear()
    ask_and_approve("tell me about topic three specifically")
    warning_lines = [line for line in captured if "Heads up" in line]
    assert len(warning_lines) == 1
    assert "@vivek has now asked about 2 of your 3 capsules in the last 30 days" in warning_lines[0]


# ---------------------------------------------------------------------
# `relay serve` headless mode: queue instead of block, `relay pending`
# resolves later
# ---------------------------------------------------------------------


def test_headless_ad_hoc_ask_is_queued_not_blocked_then_resolved_via_pending(tmp_path, registry_client, monkeypatch):
    # Never actually pop a real macOS notification during the test suite.
    notified = []
    monkeypatch.setattr(
        "wiring.flows.notify_new_approval_request",
        lambda sender, query: notified.append((sender, query)) or True,
    )

    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(
        capsule_dir, "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")
    rohan_disclosure = ephemeral_disclosure_log(tmp_path, "rohan_disclosure")
    pending_store = ephemeral_pending_approval_store(tmp_path)

    result = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )
    assert result["status"] == "pending"

    def fail_input(prompt):
        raise AssertionError("headless mode must never block on terminal input")

    # rohan's poll cycle, headless (pending_approval_store supplied) —
    # must queue + notify, never prompt, never send a response yet.
    poll_once(
        rohan, registry_client, str(capsule_dir), RateLimiter(), PendingResponseRegistry(), rohan_threads,
        rohan_disclosure, pending_approval_store=pending_store, input_fn=fail_input, now_fn=now,
    )
    assert notified == [("vivek", "how do you handle webhook retries?")]
    assert len(pending_store.list()) == 1

    # vivek's own poll: still nothing delivered — the request is
    # genuinely unanswered, not silently dropped.
    poll_once(
        vivek, registry_client, str(capsule_dir), RateLimiter(), response_registry,
        ephemeral_thread_store(tmp_path, "v2"), ephemeral_disclosure_log(tmp_path, "v2_disc"), now_fn=now,
    )
    assert response_registry.pop(result["nonce"]) is None

    # `relay pending`'s resolution — real interactive UI, just running later.
    answers = iter(["w", "1", "n"])
    pending_item = pending_store.list()[0]
    resolve_pending_approval(
        rohan, registry_client, str(capsule_dir), rohan_threads, rohan_disclosure, pending_item,
        input_fn=lambda p: next(answers), now_fn=now,
    )

    # Now the answer relays back to vivek correctly, end to end.
    poll_once(
        vivek, registry_client, str(capsule_dir), RateLimiter(), response_registry,
        ephemeral_thread_store(tmp_path, "v3"), ephemeral_disclosure_log(tmp_path, "v3_disc"), now_fn=now,
    )
    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "approved_whole"
    assert answered["cited_capsule_ids"] == ["backoff"]
    assert "exponential backoff" in answered["answer"]


def test_headless_expired_pending_approval_is_auto_denied_without_relay_pending(tmp_path, registry_client, monkeypatch):
    monkeypatch.setattr("wiring.flows.notify_new_approval_request", lambda sender, query: True)

    vivek = make_identity("vivek", tmp_path, registry_client)
    rohan = make_identity("rohan", tmp_path, registry_client)

    capsule_dir = tmp_path / "rohan_capsules"
    write_capsule(capsule_dir, "backoff", "vivek", "webhook,retry", "Use exponential backoff with jitter.")

    response_registry = PendingResponseRegistry()
    thread_store = ephemeral_thread_store(tmp_path, "vivek_threads")
    rohan_threads = ephemeral_thread_store(tmp_path, "rohan_threads")
    rohan_disclosure = ephemeral_disclosure_log(tmp_path, "rohan_disclosure")
    pending_store = ephemeral_pending_approval_store(tmp_path)

    result = ask(
        vivek, registry_client, "rohan", "how do you handle webhook retries?", response_registry, thread_store,
        wait_attempts=1, now_fn=now,
    )

    def fail_input(prompt):
        raise AssertionError("expiry auto-deny must never involve terminal input")

    poll_once(
        rohan, registry_client, str(capsule_dir), RateLimiter(), PendingResponseRegistry(), rohan_threads,
        rohan_disclosure, pending_approval_store=pending_store, input_fn=fail_input, now_fn=now,
    )
    assert len(pending_store.list()) == 1

    # Nobody ever ran `relay pending` — but a LATER poll tick (the same
    # `relay serve` poll loop, ticking again) must still auto-deny once
    # the request's own expiry_duration has passed (default 5h) — CLAUDE.md
    # §2's auto-deny-on-expiry invariant, never a silent indefinite hang.
    # Backdated directly (rather than faking a future wall-clock
    # timestamp on the outgoing signed response, which the registry's
    # own freshness check would reject as outside its validity window —
    # same lesson as the thread-expiry test above): the queued item's
    # own created_at is moved into the past; the sweep itself still runs
    # against the real, current wall clock.
    queued = pending_store.list()[0]
    queued.created_at = (now() - timedelta(hours=6)).isoformat()
    pending_store.add(queued)

    poll_once(
        rohan, registry_client, str(capsule_dir), RateLimiter(), PendingResponseRegistry(), rohan_threads,
        rohan_disclosure, pending_approval_store=pending_store, input_fn=fail_input, now_fn=now,
    )
    assert pending_store.list() == []

    poll_once(
        vivek, registry_client, str(capsule_dir), RateLimiter(), response_registry,
        ephemeral_thread_store(tmp_path, "v2"), ephemeral_disclosure_log(tmp_path, "v2_disc"), now_fn=now,
    )
    answered = response_registry.pop(result["nonce"])
    assert answered["outcome"] == "denied"
    assert answered["cited_capsule_ids"] == []


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
