# The three MCP tools' actual wiring logic, kept separate from
# agent/mcp_server.py's tool declarations so it's directly testable
# without any MCP client/transport.
#
# Every step here is a call into an already-built, already-tested
# component (resolver, approval, relay_identity, RegistryClient) — this
# module's own job is only: build the right inputs, call the right
# function, in the right order, and route the result to the right next
# call. See agent/ARCHITECTURE.md for the full ordered pipeline.

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import relay_identity as ri
from approval import ApprovalDecision, Outcome, request_approval, request_grant_promotion
from resolver.rate_limiter import RateLimiter
from resolver.resolver import resolve_scope, search_candidates
from resolver.types import ApprovalRequest, ApprovalState, Grant, GrantType, SenderIdentity

from .local_state import (
    LocalIdentity,
    encode_grant_create_payload,
    encode_grant_revoke_payload,
    load_capsules,
)
from .nonce import generate_nonce
from .registry_client import RegistryClient, RegistryRejection

DEFAULT_APPROVAL_EXPIRY = timedelta(hours=5)
MAX_REQUEST_AGE_SECS = 300  # mirrors identity's / registry's default


# ---------------------------------------------------------------------
# In-process hand-off between the poll loop (which sees ask_response
# items addressed to us) and ask()'s own bounded wait for its answer.
# Avoids two independent pollers racing to fetch_pending — only the
# poll loop ever calls it; ask() only ever reads from it.
# ---------------------------------------------------------------------


@dataclass
class PendingResponseRegistry:
    _responses: dict[str, dict] = field(default_factory=dict)

    def put(self, nonce: str, response: dict) -> None:
        self._responses[nonce] = response

    def pop(self, nonce: str) -> dict | None:
        return self._responses.pop(nonce, None)


# ---------------------------------------------------------------------
# Shared send/receive helpers (ask-request-shaped: RequestPayload +
# optional encrypted content)
# ---------------------------------------------------------------------


def _sign_and_submit(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    recipient: str,
    request_type: str,
    plaintext: bytes | None,
    now: datetime,
) -> tuple[str, int, str]:
    """Returns (nonce, timestamp, relay_item_id)."""
    nonce = generate_nonce()
    timestamp = int(now.timestamp())
    payload = ri.RequestPayload(local_identity.handle, recipient, request_type, timestamp, nonce)
    canonical_bytes, signature_bytes = ri.sign_payload(local_identity.private_key, payload)

    content_ciphertext_hex = None
    if plaintext is not None:
        recipient_identity = registry.get_identity(recipient)
        if recipient_identity is None:
            raise RegistryRejection(404, "unknown_recipient", f"{recipient!r} is not registered")
        content_ciphertext_hex = ri.encrypt(
            recipient_identity["x25519_public_key_hex"], plaintext
        ).hex()

    item_id = registry.submit_relay(
        canonical_bytes.hex(), signature_bytes.hex(), content_ciphertext_hex
    )
    return nonce, timestamp, item_id


@dataclass
class VerifiedIncoming:
    sender: str
    nonce: str
    timestamp: int
    plaintext: bytes | None


def _verify_and_decrypt(
    item: dict, local_identity: LocalIdentity, registry: RegistryClient, now: datetime
) -> VerifiedIncoming | None:
    """Re-verifies signature/timestamp locally — defense in depth, not
    trusting registry's own accept-time check alone (PRD.md §3.2 step 4:
    "Before any LLM call: Verifies the request signature... Checks
    nonce/timestamp validity window"). Returns None on any verification
    failure; caller must treat that as "reject, no further processing"."""
    sender_identity = registry.get_identity(item["sender"])
    if sender_identity is None:
        return None
    try:
        verified = ri.verify_payload(
            bytes.fromhex(item["payload_hex"]),
            bytes.fromhex(item["signature_hex"]),
            sender_identity["public_key_hex"],
            int(now.timestamp()),
            MAX_REQUEST_AGE_SECS,
        )
    except (ri.InvalidSignature, ri.MalformedPayload, ri.ExpiredOrFutureTimestamp):
        return None

    plaintext = None
    if item.get("content_ciphertext_hex"):
        try:
            plaintext = ri.decrypt(
                local_identity.encryption_key, bytes.fromhex(item["content_ciphertext_hex"])
            )
        except ri.DecryptError:
            return None

    return VerifiedIncoming(
        sender=verified.sender, nonce=verified.nonce, timestamp=verified.timestamp, plaintext=plaintext
    )


def _my_grants_as_grantor(registry: RegistryClient, local_identity: LocalIdentity, sender: str) -> list[Grant]:
    # registry's GET /grants only filters by grantee; a row's grantor
    # field isn't otherwise authenticated at read time (only at write
    # time, via grant_service.create_grant_signed), so this client-side
    # grantor==self filter is a deliberate extra guard — only grants
    # THIS identity itself created are ever trusted for local scope
    # resolution. See agent/ARCHITECTURE.md judgment calls.
    rows = registry.list_grants(grantee=sender)
    grants: list[Grant] = []
    for row in rows:
        if row["grantor"] != local_identity.handle:
            continue
        expires_at = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        grants.append(
            Grant(
                type=GrantType(row["grant_type"]),
                grantor=row["grantor"],
                grantee=row["grantee"],
                capsule_ids=frozenset(row["scope_capsule_ids"]),
                revoked=row["revoked_at"] is not None,
                expires_at=expires_at,
            )
        )
    return grants


# ---------------------------------------------------------------------
# relay ask — caller side
# ---------------------------------------------------------------------


def ask(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    recipient: str,
    question: str,
    response_registry: PendingResponseRegistry,
    *,
    wait_attempts: int = 5,
    wait_interval: float = 1.0,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict:
    now = now_fn()
    nonce, _timestamp, item_id = _sign_and_submit(
        local_identity, registry, recipient, "ask", question.encode("utf-8"), now
    )

    for attempt in range(wait_attempts):
        response = response_registry.pop(nonce)
        if response is not None:
            return {"status": "answered", "request_id": item_id, **response}
        if attempt < wait_attempts - 1:
            sleep_fn(wait_interval)

    # No websockets/push (out of scope) — caller's own poll loop will
    # eventually deliver this via response_registry; nothing further to
    # do here within one bounded tool call.
    return {"status": "pending", "request_id": item_id, "nonce": nonce}


# ---------------------------------------------------------------------
# relay ask — recipient side: incoming "ask" item
# ---------------------------------------------------------------------


def _build_denial_response(reason: str) -> dict:
    return {"outcome": "denied", "answer": f"Request denied: {reason}", "cited_capsule_ids": []}


def _build_response_from_decision(decision: ApprovalDecision, capsules_by_id: dict) -> dict:
    if decision.outcome is Outcome.APPROVED_WHOLE:
        cited = list(decision.approved_capsule_ids)
        answer = "\n\n---\n\n".join(capsules_by_id[cid].content for cid in cited)
        return {"outcome": "approved_whole", "answer": answer, "cited_capsule_ids": cited}
    if decision.outcome is Outcome.APPROVED_EXCERPT:
        excerpt = decision.excerpt
        content = capsules_by_id[excerpt.capsule_id].content[excerpt.start : excerpt.end]
        return {"outcome": "approved_excerpt", "answer": content, "cited_capsule_ids": [excerpt.capsule_id]}
    if decision.outcome is Outcome.MANUAL_ANSWER:
        # No capsule content leaves the machine at all in this case —
        # the manual answer IS the entire released content (approval/'s
        # own invariant, preserved here).
        return {"outcome": "manual_answer", "answer": decision.manual_answer, "cited_capsule_ids": []}
    if decision.outcome is Outcome.EXPIRED:
        return _build_denial_response("approval request expired before it was answered")
    return _build_denial_response("not approved")


def process_incoming_ask(
    item: dict,
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    expiry_duration: timedelta = DEFAULT_APPROVAL_EXPIRY,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    now = now_fn()
    verified = _verify_and_decrypt(item, local_identity, registry, now)
    if verified is None:
        return  # fails closed: an unverifiable request gets no response at all

    sender = verified.sender
    query = (verified.plaintext or b"").decode("utf-8", errors="replace")

    if not rate_limiter.check_and_record(sender, now):
        response = _build_denial_response("rate limit exceeded")
    else:
        capsules_by_id = load_capsules(capsule_dir)
        my_grants = _my_grants_as_grantor(registry, local_identity, sender)
        permitted = resolve_scope(SenderIdentity(sender), my_grants, capsules_by_id, now)

        if permitted:
            # Standing-grant branch — no live approval prompt (PRD.md
            # §3.1 step 5): the existing grant already IS consent.
            cited = sorted(permitted)
            answer = "\n\n---\n\n".join(capsules_by_id[cid].content for cid in cited)
            response = {"outcome": "approved_whole", "answer": answer, "cited_capsule_ids": cited}
        else:
            # Ad hoc branch (PRD.md §3.2): deterministic candidate
            # search, then a live, blocking terminal approval prompt.
            candidate_ids = search_candidates(SenderIdentity(sender), query, list(capsules_by_id.values()))
            approval_request = ApprovalRequest(
                sender=sender,
                query=query,
                created_at=now,
                expiry_duration=expiry_duration,
                candidate_capsule_ids=candidate_ids,
                state=ApprovalState.PENDING,
            )
            decision = request_approval(
                approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn, now=now
            )
            response = _build_response_from_decision(decision, capsules_by_id)

            promotion = request_grant_promotion(
                decision, approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn
            )
            if promotion is not None:
                # Separate registry call from the response relay below —
                # never conflated into one request (this task's explicit
                # requirement 3f).
                try:
                    grant(
                        local_identity,
                        registry,
                        promotion.grantee_handle,
                        "standing",
                        list(promotion.capsule_ids),
                        now_fn=now_fn,
                    )
                except RegistryRejection:
                    pass  # promotion is best-effort; the answer itself still goes out below

    response["in_reply_to_nonce"] = verified.nonce
    _sign_and_submit(
        local_identity, registry, sender, "ask_response", json.dumps(response).encode("utf-8"), now_fn()
    )


# ---------------------------------------------------------------------
# relay ask — caller side: incoming "ask_response" item
# ---------------------------------------------------------------------


def process_incoming_ask_response(
    item: dict,
    local_identity: LocalIdentity,
    registry: RegistryClient,
    response_registry: PendingResponseRegistry,
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    verified = _verify_and_decrypt(item, local_identity, registry, now_fn())
    if verified is None or verified.plaintext is None:
        return
    response = json.loads(verified.plaintext.decode("utf-8"))
    response_registry.put(response["in_reply_to_nonce"], response)


# ---------------------------------------------------------------------
# poll loop (responsibility #5) — the only place that calls fetch_pending
# ---------------------------------------------------------------------


def poll_once(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    response_registry: PendingResponseRegistry,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> int:
    items = registry.fetch_pending(local_identity.handle)
    for item in items:
        if item["request_type"] == "ask":
            process_incoming_ask(
                item,
                local_identity,
                registry,
                capsule_dir,
                rate_limiter,
                input_fn=input_fn,
                output_fn=output_fn,
                now_fn=now_fn,
            )
        elif item["request_type"] == "ask_response":
            process_incoming_ask_response(item, local_identity, registry, response_registry, now_fn=now_fn)
        # Unknown request_type: no handler, item is dropped — fails
        # closed (no response, no state change) rather than guessing.
    return len(items)


def run_poll_loop(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    response_registry: PendingResponseRegistry,
    *,
    interval_secs: float = 5.0,
    iterations: int | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    # ponytail: fixed-interval poll, no backoff/circuit-breaker tuning —
    # explicitly the simplest thing this task's scope allows.
    count = 0
    while iterations is None or count < iterations:
        poll_once(
            local_identity, registry, capsule_dir, rate_limiter, response_registry,
            input_fn=input_fn, output_fn=output_fn,
        )
        count += 1
        if iterations is None or count < iterations:
            sleep_fn(interval_secs)


# ---------------------------------------------------------------------
# relay grant / relay revoke
# ---------------------------------------------------------------------


def grant(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    grantee: str,
    grant_type: str,
    scope_capsule_ids: list[str],
    expires_at: datetime | None = None,
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> str:
    now = now_fn()
    timestamp = int(now.timestamp())
    nonce = generate_nonce()
    expires_at_ts = int(expires_at.timestamp()) if expires_at is not None else None

    canonical_bytes = encode_grant_create_payload(
        local_identity.handle, grantee, grant_type, scope_capsule_ids, expires_at_ts, timestamp, nonce
    )
    signature_hex = ri.sign_bytes(local_identity.private_key, canonical_bytes).hex()

    return registry.create_grant(
        grantor=local_identity.handle,
        grantee=grantee,
        grant_type=grant_type,
        scope_capsule_ids=scope_capsule_ids,
        timestamp=timestamp,
        nonce=nonce,
        signature_hex=signature_hex,
        expires_at=expires_at,
    )


def revoke(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    grant_id: str,
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    now = now_fn()
    timestamp = int(now.timestamp())
    nonce = generate_nonce()

    canonical_bytes = encode_grant_revoke_payload(grant_id, timestamp, nonce)
    signature_hex = ri.sign_bytes(local_identity.private_key, canonical_bytes).hex()

    registry.revoke_grant(grant_id, timestamp, nonce, signature_hex)
