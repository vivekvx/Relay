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
from resolver.resolver import (
    DEFAULT_ENUMERATION_ABSOLUTE_THRESHOLD,
    DEFAULT_ENUMERATION_FRACTION_THRESHOLD,
    DEFAULT_ENUMERATION_WINDOW,
    enumeration_flag,
    resolve_scope,
    search_candidates,
    split_thread_candidates,
)
from resolver.types import ApprovalRequest, ApprovalState, Grant, GrantType, SenderIdentity

from .disclosure_log import DisclosureLog
from .local_state import (
    LocalIdentity,
    encode_grant_create_payload,
    encode_grant_revoke_payload,
    load_capsules,
)
from .nonce import generate_nonce
from .notifications import notify_new_approval_request
from .pending_approvals import PendingApproval, PendingApprovalStore
from .registry_client import RegistryClient, RegistryRejection
from .threads import ThreadStore

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
    thread_store: ThreadStore,
    *,
    thread_id: str | None = None,
    reason: str = "",
    urgency: str = "",
    wait_attempts: int = 5,
    wait_interval: float = 1.0,
    sleep_fn: Callable[[float], None] = time.sleep,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict:
    now = now_fn()
    # thread_id: caller-supplied to continue an existing conversation, or
    # freshly generated (same random-hex shape as a nonce) to start a new
    # one. Carried only inside the encrypted content — the registry has
    # no field for it and never sees it (threads.py's module docstring).
    thread_id = thread_id or generate_nonce()
    # reason/urgency: structured pre-ask context, bundled as distinct
    # fields (never concatenated into `question`) — purely informational
    # for the approver's terminal display; resolve_scope/search_candidates
    # only ever see `question` (see resolver.types.ApprovalRequest's
    # docstring on this same point).
    content = json.dumps({"question": question, "thread_id": thread_id, "reason": reason, "urgency": urgency})
    nonce, _timestamp, item_id = _sign_and_submit(
        local_identity, registry, recipient, "ask", content.encode("utf-8"), now
    )

    thread_store.get_or_create(thread_id, sender=local_identity.handle, recipient=recipient, now=now)
    thread_store.record_message(thread_id, question=question, answer="", outcome="pending", now=now, nonce=nonce)

    for attempt in range(wait_attempts):
        response = response_registry.pop(nonce)
        if response is not None:
            thread_store.finalize_message(
                thread_id, nonce, answer=response.get("answer", ""), outcome=response.get("outcome", "answered"),
                now=now_fn(),
            )
            return {"status": "answered", "request_id": nonce, "thread_id": thread_id, **response}
        if attempt < wait_attempts - 1:
            sleep_fn(wait_interval)

    # No websockets/push (out of scope) — caller's own poll loop will
    # eventually deliver this via response_registry; nothing further to
    # do here within one bounded tool call. `request_id` is the nonce,
    # not the relay queue's own item_id: response_registry is only ever
    # keyed by nonce, so surfacing item_id here as "request_id" would be
    # a value nothing downstream (including check_pending below) could
    # actually use — confirmed by hitting exactly that mistake in this
    # feature's own MCP-protocol test. `relay_item_id` carries the
    # original registry row id for anyone who needs it for other reasons
    # (e.g. audit lookups); it is never the thing to pass to `relay check`.
    # The still-pending placeholder message left in thread_store above
    # gets filled in later by process_incoming_ask_response's own
    # finalize_message call, out-of-band, once a later poll cycle
    # delivers the answer.
    return {
        "status": "pending",
        "request_id": nonce,
        "nonce": nonce,
        "thread_id": thread_id,
        "relay_item_id": item_id,
        "message": (
            f"not answered yet — check back with `relay check {nonce}`\n"
            f"Thread: {thread_id} — reply with: relay ask {recipient} '...' --thread {thread_id}"
        ),
    }


# ---------------------------------------------------------------------
# relay check — manual follow-up on a pending ask, from a later process
# ---------------------------------------------------------------------


def check_pending(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    response_registry: PendingResponseRegistry,
    thread_store: ThreadStore,
    disclosure_log: DisclosureLog,
    nonce: str,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict:
    """One-shot manual follow-up for `ask()`'s "pending" case, run from a
    fresh process (no background poll thread survives past `ask()`'s own
    process exit). Reuses poll_once exactly as run_poll_loop does — a
    single round, not a new polling mechanism — so any other incoming
    "ask" item due to us still gets its live approval prompt, and any
    other "ask_response" still lands safely in response_registry rather
    than being silently dropped by the registry's own delivered-once
    semantics.

    `nonce` is ask()'s "pending" response's `request_id` field (which is
    the nonce, not the relay queue's `relay_item_id` — see ask()'s own
    comment) — the only value response_registry is actually keyed by."""
    poll_once(
        local_identity, registry, capsule_dir, rate_limiter, response_registry, thread_store, disclosure_log,
        input_fn=input_fn, output_fn=output_fn, now_fn=now_fn,
    )
    response = response_registry.pop(nonce)
    if response is not None:
        thread_store.finalize_message(
            response.get("thread_id", ""), nonce, answer=response.get("answer", ""),
            outcome=response.get("outcome", "answered"), now=now_fn(),
        )
        return {"status": "answered", "request_id": nonce, **response}
    return {
        "status": "pending",
        "request_id": nonce,
        "message": f"not answered yet — check back with `relay check {nonce}`",
    }


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
    thread_store: ThreadStore,
    disclosure_log: DisclosureLog,
    *,
    pending_approval_store: PendingApprovalStore | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    expiry_duration: timedelta = DEFAULT_APPROVAL_EXPIRY,
    enumeration_window: timedelta = DEFAULT_ENUMERATION_WINDOW,
    enumeration_fraction_threshold: float = DEFAULT_ENUMERATION_FRACTION_THRESHOLD,
    enumeration_absolute_threshold: int = DEFAULT_ENUMERATION_ABSOLUTE_THRESHOLD,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    now = now_fn()
    verified = _verify_and_decrypt(item, local_identity, registry, now)
    if verified is None:
        return  # fails closed: an unverifiable request gets no response at all

    sender = verified.sender
    raw = (verified.plaintext or b"").decode("utf-8", errors="replace")
    try:
        payload = json.loads(raw)
        query = payload.get("question", "")
        thread_id = payload.get("thread_id") or generate_nonce()
        reason = payload.get("reason", "")
        urgency = payload.get("urgency", "")
    except (json.JSONDecodeError, AttributeError):
        # Pre-threading / malformed caller: treat the whole plaintext as
        # the question and start an untracked one-off thread — never a
        # hard failure just because thread/reason/urgency metadata is
        # missing.
        query = raw
        thread_id = generate_nonce()
        reason = ""
        urgency = ""

    thread = thread_store.get_or_create(thread_id, sender=sender, recipient=local_identity.handle, now=now)

    # Rate limiting is still per-message, unaffected by threading (R3):
    # this check runs once per incoming "ask" item regardless of which
    # thread it belongs to.
    promotion = None
    if not rate_limiter.check_and_record(sender, now):
        response = _build_denial_response("rate limit exceeded")
    else:
        capsules_by_id = load_capsules(capsule_dir)
        my_grants = _my_grants_as_grantor(registry, local_identity, sender)
        permitted = resolve_scope(SenderIdentity(sender), my_grants, capsules_by_id, now)

        if permitted:
            # Standing-grant branch — no live approval prompt (PRD.md
            # §3.1 step 5): the existing grant already IS consent. Not
            # affected by conversation threading at all — standing
            # grants and ad hoc per-thread accumulation are deliberately
            # separate mechanisms (this task's explicit scope boundary).
            cited = sorted(permitted)
            answer = "\n\n---\n\n".join(capsules_by_id[cid].content for cid in cited)
            response = {"outcome": "approved_whole", "answer": answer, "cited_capsule_ids": cited}
        else:
            # Ad hoc branch (PRD.md §3.2): deterministic candidate
            # search, then a live, blocking terminal approval prompt —
            # UNLESS every candidate this query surfaced is already in
            # this thread's approved-scope-set, in which case it's a
            # same-scope follow-up (CASE A) and skips the prompt.
            # search_candidates now returns SearchCandidate objects (match
            # reason/span, for approval/'s richer rendering) — flows.py
            # only ever needed bare capsule IDs for ApprovalRequest, so
            # unwrap here rather than changing candidate_capsule_ids' type.
            candidate_ids = tuple(
                c.capsule_id
                for c in search_candidates(SenderIdentity(sender), query, list(capsules_by_id.values()))
            )

            # An inactivity-expired thread's accumulated consent is not
            # honored — safe default, never a silent auto-grant past the
            # conversation's own expiry (threads.py's is_expired doc).
            approved_so_far = (
                frozenset() if thread.is_expired(now) else frozenset(thread.approved_capsule_ids)
            )
            new_candidate_ids, reusable_ids = split_thread_candidates(candidate_ids, approved_so_far)

            if candidate_ids and not new_candidate_ids:
                # CASE A: same-scope follow-up. Deterministic membership
                # check only — never an LLM judgment about topical
                # relatedness (this task's explicit DO NOT BUILD).
                cited = sorted(reusable_ids)
                answer = "\n\n---\n\n".join(capsules_by_id[cid].content for cid in cited)
                response = {"outcome": "approved_whole", "answer": answer, "cited_capsule_ids": cited}
            else:
                # CASE B (or a brand-new thread): live approval, scoped to
                # only the NEW candidates — never re-prompting for
                # capsules this conversation already approved.
                #
                # Anti-enumeration advisory (PRD.md §5 R3): computed from
                # this sender's disclosure history PRIOR to this request
                # (this request's own disclosures are recorded below,
                # after the decision, so they count toward the NEXT
                # request's warning, not this one) — purely advisory, an
                # extra line in the SAME prompt, never a separate
                # blocking step (this task's explicit DO NOT BUILD).
                distinct_seen = disclosure_log.distinct_capsules_in_window(sender, now, enumeration_window)
                enumeration_warning = None
                if enumeration_flag(
                    len(distinct_seen), len(capsules_by_id),
                    fraction_threshold=enumeration_fraction_threshold,
                    absolute_threshold=enumeration_absolute_threshold,
                ):
                    window_days = enumeration_window.days
                    enumeration_warning = (
                        f"Heads up: @{sender} has now asked about {len(distinct_seen)} of your "
                        f"{len(capsules_by_id)} capsules in the last {window_days} days — this may be "
                        f"broader information-gathering rather than a specific question. Proceed anyway?"
                    )

                approval_request = ApprovalRequest(
                    sender=sender,
                    query=query,
                    created_at=now,
                    expiry_duration=expiry_duration,
                    candidate_capsule_ids=new_candidate_ids,
                    state=ApprovalState.PENDING,
                    reason=reason,
                    urgency=urgency,
                    enumeration_warning=enumeration_warning,
                )

                if pending_approval_store is not None:
                    # Headless (`relay serve`): no terminal to block on —
                    # queue it instead of calling request_approval, fire a
                    # native notification, and leave the requester in
                    # "pending" exactly like today's bounded-wait timeout
                    # case (ask()'s own poll loop already handles that).
                    # `relay pending` is the only place that later calls
                    # request_approval against this, with the exact same
                    # interactive UI — see resolve_pending_approval below.
                    pending_approval_store.add(PendingApproval(
                        nonce=verified.nonce,
                        sender=sender,
                        thread_id=thread_id,
                        query=query,
                        created_at=now.isoformat(),
                        expiry_seconds=int(expiry_duration.total_seconds()),
                        candidate_capsule_ids=list(new_candidate_ids),
                        reusable_capsule_ids=sorted(reusable_ids),
                        reason=reason,
                        urgency=urgency,
                        enumeration_warning=enumeration_warning,
                    ))
                    notify_new_approval_request(sender, query)
                    thread_store.record_message(
                        thread_id, question=query, answer="", outcome="pending", now=now, nonce=verified.nonce,
                    )
                    return

                decision = request_approval(
                    approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn, now=now
                )
                response = _build_response_from_decision(decision, capsules_by_id)

                if decision.outcome is Outcome.APPROVED_WHOLE:
                    # Only whole-document approval extends the reusable
                    # set — an excerpt approval must never let a later
                    # follow-up auto-continue into the REST of that same
                    # document without its own approval.
                    thread_store.add_approved_capsules(thread_id, frozenset(decision.approved_capsule_ids))
                    disclosure_log.record(sender, frozenset(decision.approved_capsule_ids), now)
                    if reusable_ids:
                        response["cited_capsule_ids"] = sorted(set(response["cited_capsule_ids"]) | reusable_ids)
                        response["answer"] = "\n\n---\n\n".join(
                            capsules_by_id[cid].content for cid in response["cited_capsule_ids"]
                        )
                elif decision.outcome is Outcome.APPROVED_EXCERPT:
                    # An excerpt still discloses (part of) this capsule —
                    # counts toward the sender's cumulative footprint even
                    # though it doesn't extend the thread's whole-document
                    # reusable set (see the APPROVED_WHOLE branch above).
                    disclosure_log.record(sender, frozenset({decision.excerpt.capsule_id}), now)

                promotion = request_grant_promotion(
                    decision, approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn
                )

    # thread_id/message history recorded for every branch (standing
    # grant, rate-limited, and ad hoc) — a thread's history is a log of
    # the conversation, not just of its ad hoc-approval decisions.
    response["thread_id"] = thread_id
    thread_store.record_message(
        thread_id, question=query, answer=response.get("answer", ""),
        outcome=response.get("outcome", ""), now=now,
    )

    if promotion is not None:
        # Separate registry call from the response relay below — never
        # conflated into one request (this task's explicit requirement 3f).
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
# relay pending — resolving a queued (headless) ad hoc approval request
# ---------------------------------------------------------------------


def list_pending_approvals_with_candidates(capsule_dir: str, pending_approval_store: PendingApprovalStore) -> list[dict]:
    """Read-only: everything an approver-side interface (terminal or
    MCP's relay_pending_requests) needs to DISPLAY a queued request —
    never a decision-making function itself. Recomputes match_reason/
    relevant_span via the real search_candidates fresh against the
    current capsule store (never trusts a stale snapshot from when the
    request was queued — same principle resolve_pending_approval's own
    docstring states), filtered down to exactly the candidate_capsule_ids
    the request was actually queued with (a capsule search_candidates
    would surface today but that wasn't a candidate when queued is not
    shown — the approver is answering the ORIGINAL request, not a new
    search)."""
    capsules_by_id = load_capsules(capsule_dir)
    results = []
    for pending in pending_approval_store.list():
        search_results = search_candidates(SenderIdentity(pending.sender), pending.query, list(capsules_by_id.values()))
        match_info = {c.capsule_id: c for c in search_results}
        candidates = [
            {
                "capsule_id": cid,
                "match_reason": match_info[cid].match_reason if cid in match_info else None,
                "relevant_span": match_info[cid].relevant_span if cid in match_info else None,
            }
            for cid in pending.candidate_capsule_ids
        ]
        approval_request = pending.to_approval_request()
        results.append({
            "request_id": pending.nonce,
            "sender": pending.sender,
            "thread_id": pending.thread_id,
            "question": pending.query,
            "reason": pending.reason,
            "urgency": pending.urgency,
            "enumeration_warning": pending.enumeration_warning,
            "candidates": candidates,
            "expires_at": approval_request.expires_at.isoformat(),
        })
    return results


def resolve_pending_approval(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    thread_store: ThreadStore,
    disclosure_log: DisclosureLog,
    pending: PendingApproval,
    *,
    decision: ApprovalDecision | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict:
    """`relay pending`'s per-item resolution — the exact same
    request_approval/request_grant_promotion interactive UI
    process_incoming_ask would have used live, just running later, from
    a real terminal, against a request queued while headless. Reloads
    capsules fresh (never trusts a stale snapshot from when the request
    first arrived) and sends the ask_response itself, since the
    original process_incoming_ask call returned without sending one.

    `decision`: when the caller (relay_respond_to_request, an MCP tool —
    see mcp_server.py) already has an unambiguous, fully-validated
    ApprovalDecision built from structured arguments, pass it here to
    skip request_approval's terminal input() entirely — everything
    after the decision (thread/disclosure bookkeeping, grant promotion,
    sending the response) is identical either way, one code path, never
    duplicated. When omitted (the `relay pending` terminal path),
    request_approval runs exactly as before."""
    now = now_fn()
    capsules_by_id = load_capsules(capsule_dir)
    approval_request = pending.to_approval_request()

    if decision is None:
        decision = request_approval(approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn, now=now)
    response = _build_response_from_decision(decision, capsules_by_id)

    reusable_ids = frozenset(pending.reusable_capsule_ids)
    if decision.outcome is Outcome.APPROVED_WHOLE:
        thread_store.add_approved_capsules(pending.thread_id, frozenset(decision.approved_capsule_ids))
        disclosure_log.record(pending.sender, frozenset(decision.approved_capsule_ids), now)
        if reusable_ids:
            response["cited_capsule_ids"] = sorted(set(response["cited_capsule_ids"]) | reusable_ids)
            response["answer"] = "\n\n---\n\n".join(
                capsules_by_id[cid].content for cid in response["cited_capsule_ids"]
            )
    elif decision.outcome is Outcome.APPROVED_EXCERPT:
        disclosure_log.record(pending.sender, frozenset({decision.excerpt.capsule_id}), now)

    promotion = request_grant_promotion(
        decision, approval_request, capsules_by_id, input_fn=input_fn, output_fn=output_fn
    )

    response["thread_id"] = pending.thread_id
    thread_store.finalize_message(
        pending.thread_id, pending.nonce, answer=response.get("answer", ""),
        outcome=response.get("outcome", ""), now=now,
    )

    if promotion is not None:
        try:
            grant(
                local_identity, registry, promotion.grantee_handle, "standing", list(promotion.capsule_ids),
                now_fn=now_fn,
            )
        except RegistryRejection:
            pass  # promotion is best-effort; the answer itself still goes out below

    response["in_reply_to_nonce"] = pending.nonce
    _sign_and_submit(
        local_identity, registry, pending.sender, "ask_response", json.dumps(response).encode("utf-8"), now_fn()
    )
    return response


def sweep_expired_pending_approvals(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    thread_store: ThreadStore,
    pending_approval_store: PendingApprovalStore,
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> int:
    """Auto-deny-on-expiry (PRD.md §5 R5, CLAUDE.md §2) for requests that
    were queued headless and never reached a human via `relay pending`
    before their own expiry_duration elapsed — an unanswered request
    left sitting in the queue must never silently sit there past its
    expiry; this makes the deny happen even if nobody ever runs `relay
    pending`. Called every poll_once tick when a pending_approval_store
    is in use (i.e. only under `relay serve`/headless mode)."""
    now = now_fn()
    expired = pending_approval_store.pop_expired(now)
    for pending in expired:
        response = _build_denial_response("approval request expired before it was answered")
        response["thread_id"] = pending.thread_id
        thread_store.finalize_message(
            pending.thread_id, pending.nonce, answer=response["answer"], outcome="denied", now=now,
        )
        response["in_reply_to_nonce"] = pending.nonce
        _sign_and_submit(
            local_identity, registry, pending.sender, "ask_response", json.dumps(response).encode("utf-8"), now,
        )
    return len(expired)


# ---------------------------------------------------------------------
# relay ask — caller side: incoming "ask_response" item
# ---------------------------------------------------------------------


def process_incoming_ask_response(
    item: dict,
    local_identity: LocalIdentity,
    registry: RegistryClient,
    response_registry: PendingResponseRegistry,
    thread_store: ThreadStore,
    *,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> None:
    verified = _verify_and_decrypt(item, local_identity, registry, now_fn())
    if verified is None or verified.plaintext is None:
        return
    response = json.loads(verified.plaintext.decode("utf-8"))
    response_registry.put(response["in_reply_to_nonce"], response)
    # Out-of-band completion path: ask()'s own bounded wait already
    # timed out and returned "pending" before this response arrived, so
    # ask() itself never got to finalize its placeholder message — this
    # poll cycle is the only place left that can. No-op if ask() already
    # finalized it via its own in-wait return (ThreadStore.finalize_message
    # matches by nonce and is idempotent to call twice).
    thread_store.finalize_message(
        response.get("thread_id", ""), response["in_reply_to_nonce"],
        answer=response.get("answer", ""), outcome=response.get("outcome", "answered"), now=now_fn(),
    )


# ---------------------------------------------------------------------
# poll loop (responsibility #5) — the only place that calls fetch_pending
# ---------------------------------------------------------------------


def poll_once(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    response_registry: PendingResponseRegistry,
    thread_store: ThreadStore,
    disclosure_log: DisclosureLog,
    *,
    pending_approval_store: PendingApprovalStore | None = None,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    now_fn: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> int:
    if pending_approval_store is not None:
        # Headless mode's auto-deny-on-expiry sweep — see
        # sweep_expired_pending_approvals's docstring. A no-op cost when
        # nothing is queued/expired.
        sweep_expired_pending_approvals(
            local_identity, registry, thread_store, pending_approval_store, now_fn=now_fn,
        )
    items = registry.fetch_pending(local_identity.handle)
    for item in items:
        if item["request_type"] == "ask":
            process_incoming_ask(
                item,
                local_identity,
                registry,
                capsule_dir,
                rate_limiter,
                thread_store,
                disclosure_log,
                pending_approval_store=pending_approval_store,
                input_fn=input_fn,
                output_fn=output_fn,
                now_fn=now_fn,
            )
        elif item["request_type"] == "ask_response":
            process_incoming_ask_response(
                item, local_identity, registry, response_registry, thread_store, now_fn=now_fn
            )
        # Unknown request_type: no handler, item is dropped — fails
        # closed (no response, no state change) rather than guessing.
    return len(items)


def run_poll_loop(
    local_identity: LocalIdentity,
    registry: RegistryClient,
    capsule_dir: str,
    rate_limiter: RateLimiter,
    response_registry: PendingResponseRegistry,
    thread_store: ThreadStore,
    disclosure_log: DisclosureLog,
    *,
    pending_approval_store: PendingApprovalStore | None = None,
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
            local_identity, registry, capsule_dir, rate_limiter, response_registry, thread_store, disclosure_log,
            pending_approval_store=pending_approval_store, input_fn=input_fn, output_fn=output_fn,
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
