from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

# Deliberately import resolver's real module too, not just what approval/
# re-exports — proves this is a real integration, not approval/ quietly
# redefining its own parallel Capsule/ApprovalRequest.
from resolver.types import ApprovalRequest, ApprovalState, Capsule

from approval import (
    ApprovalDecision,
    GrantPromotion,
    Outcome,
    request_approval,
    request_grant_promotion,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_request(*, state=ApprovalState.PENDING, expiry_duration=timedelta(hours=4), candidate_ids=("cap-a", "cap-b")):
    return ApprovalRequest(
        sender="vivek",
        query="how do you handle retry logic for webhooks?",
        created_at=NOW - timedelta(minutes=5),
        expiry_duration=expiry_duration,
        candidate_capsule_ids=candidate_ids,
        state=state,
    )


def make_capsules_by_id():
    return {
        "cap-a": Capsule(
            id="cap-a",
            shareable=True,
            shareable_with=frozenset({"vivek"}),
            tags=frozenset({"webhook", "retry"}),
            content="Use exponential backoff with jitter for webhook retries.",
        ),
        "cap-b": Capsule(
            id="cap-b",
            shareable=True,
            shareable_with=frozenset({"vivek"}),
            tags=frozenset({"incident"}),
            content="Some unrelated incident detail here.",
        ),
    }


def fake_io(*answers):
    it = iter(answers)

    def input_fn(prompt):
        return next(it)

    return input_fn, (lambda line: None)


# --- distinct outcomes -----------------------------------------------------


def test_approve_whole_single_doc():
    input_fn, output_fn = fake_io("w", "1")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.APPROVED_WHOLE
    assert decision.approved_capsule_ids == ("cap-a",)
    assert decision.excerpt is None
    assert decision.manual_answer is None


def test_approve_whole_multiple_docs():
    input_fn, output_fn = fake_io("whole", "1,2")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.APPROVED_WHOLE
    assert decision.approved_capsule_ids == ("cap-a", "cap-b")


def test_approve_excerpt_carries_manually_typed_bounds():
    # No suggested-span shortcut exists (resolver supplies no span) — the
    # approver always types bounds directly.
    input_fn, output_fn = fake_io("e", "1", "4,34")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.APPROVED_EXCERPT
    assert decision.excerpt.capsule_id == "cap-a"
    assert (decision.excerpt.start, decision.excerpt.end) == (4, 34)


def test_approve_excerpt_different_bounds_on_second_candidate():
    input_fn, output_fn = fake_io("e", "2", "5,15")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.APPROVED_EXCERPT
    assert decision.excerpt.capsule_id == "cap-b"
    assert (decision.excerpt.start, decision.excerpt.end) == (5, 15)


def test_deny():
    input_fn, output_fn = fake_io("d")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.DENIED


def test_manual_answer_is_distinct_outcome_no_capsule_content():
    input_fn, output_fn = fake_io("m", "We use exponential backoff, see the wiki.")
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.MANUAL_ANSWER
    assert decision.manual_answer == "We use exponential backoff, see the wiki."
    assert decision.approved_capsule_ids == ()
    assert decision.excerpt is None


# --- default-safe on invalid/ambiguous input -------------------------------


@pytest.mark.parametrize(
    "answers",
    [
        ("banana",),  # unrecognized top-level choice
        ("",),  # empty top-level choice
        ("w", "banana"),  # non-numeric doc pick
        ("w", "99"),  # out-of-range doc pick
        ("w", ""),  # empty doc pick
        ("w", "1,99"),  # one valid, one out-of-range
        ("e", "99"),  # out-of-range doc for excerpt
        ("e", "1", "not-a-span"),  # malformed span
        ("e", "1", "30,5"),  # start >= end
        ("e", "1", "0,999"),  # end past content length
        ("m", ""),  # empty manual answer
        ("m", "   "),  # whitespace-only manual answer
    ],
)
def test_invalid_or_ambiguous_input_defaults_to_denied(answers):
    input_fn, output_fn = fake_io(*answers)
    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.DENIED


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_interrupt_or_eof_at_top_level_defaults_to_denied(exc):
    def input_fn(prompt):
        raise exc

    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=lambda line: None, now=NOW)
    assert decision.outcome is Outcome.DENIED


def test_interrupt_mid_flow_defaults_to_denied():
    answers = iter(["w"])

    def input_fn(prompt):
        try:
            return next(answers)
        except StopIteration:
            raise EOFError

    decision = request_approval(make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=lambda line: None, now=NOW)
    assert decision.outcome is Outcome.DENIED


# --- already-expired request short-circuits, no prompt ---------------------


def test_already_expired_request_short_circuits_without_prompting():
    calls = []

    def input_fn(prompt):
        calls.append(prompt)
        return "w"  # would approve everything if it were ever reached

    def output_fn(line):
        calls.append(line)

    request = make_request(expiry_duration=timedelta(hours=-1))  # created_at + (-1h) already past
    decision = request_approval(request, make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)

    assert decision.outcome is Outcome.EXPIRED
    assert calls == []  # nothing was rendered, nothing was asked


def test_request_already_marked_expired_short_circuits_even_if_expires_at_in_future():
    calls = []
    request = make_request(state=ApprovalState.EXPIRED, expiry_duration=timedelta(hours=4))
    decision = request_approval(
        request,
        make_capsules_by_id(),
        input_fn=lambda p: calls.append(p) or "w",
        output_fn=lambda line: calls.append(line),
        now=NOW,
    )
    assert decision.outcome is Outcome.EXPIRED
    assert calls == []


# --- missing candidate capsule is skipped, not a crash ---------------------


def test_candidate_id_missing_from_capsule_store_is_dropped_not_fatal():
    request = make_request(candidate_ids=("cap-a", "cap-ghost"))
    input_fn, output_fn = fake_io("w", "1")
    decision = request_approval(request, make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn, now=NOW)
    assert decision.outcome is Outcome.APPROVED_WHOLE
    assert decision.approved_capsule_ids == ("cap-a",)


# --- grant promotion is structurally separate -------------------------------


def test_grant_promotion_type_has_no_overlap_with_approval_decision_fields():
    # Type-level proof, not just a today-they-happen-to-differ assertion:
    # GrantPromotion's field set and ApprovalDecision's field set are
    # disjoint, so a caller cannot accidentally read a grant-promotion
    # value out of an ApprovalDecision instance or vice versa.
    decision_fields = set(ApprovalDecision.__dataclass_fields__)
    grant_fields = set(GrantPromotion.__dataclass_fields__)
    assert decision_fields.isdisjoint(grant_fields)


def test_grant_promotion_offered_and_accepted_after_approval():
    decision = ApprovalDecision(outcome=Outcome.APPROVED_WHOLE, approved_capsule_ids=("cap-a",), decided_at=NOW)
    input_fn, output_fn = fake_io("y", "onboarding docs")
    promotion = request_grant_promotion(decision, make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn)
    assert isinstance(promotion, GrantPromotion)
    assert promotion.grantee_handle == "vivek"
    assert promotion.scope_description == "onboarding docs"
    assert promotion.capsule_ids == ("cap-a",)


def test_grant_promotion_declined_returns_none():
    decision = ApprovalDecision(outcome=Outcome.DENIED, decided_at=NOW)
    input_fn, output_fn = fake_io("n")
    promotion = request_grant_promotion(decision, make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=output_fn)
    assert promotion is None


def test_grant_promotion_not_offered_after_manual_answer():
    decision = ApprovalDecision(outcome=Outcome.MANUAL_ANSWER, manual_answer="short answer", decided_at=NOW)

    def input_fn(prompt):
        raise AssertionError("must not prompt after MANUAL_ANSWER")

    promotion = request_grant_promotion(decision, make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=lambda l: None)
    assert promotion is None


def test_grant_promotion_not_offered_after_expired():
    decision = ApprovalDecision(outcome=Outcome.EXPIRED, decided_at=NOW)

    def input_fn(prompt):
        raise AssertionError("must not prompt after EXPIRED")

    promotion = request_grant_promotion(decision, make_request(), make_capsules_by_id(), input_fn=input_fn, output_fn=lambda l: None)
    assert promotion is None


# --- ApprovalDecision shape invariants (types.py) --------------------------


def test_approved_whole_requires_capsule_ids():
    with pytest.raises(ValueError):
        ApprovalDecision(outcome=Outcome.APPROVED_WHOLE)


def test_approved_excerpt_requires_bounds():
    with pytest.raises(ValueError):
        ApprovalDecision(outcome=Outcome.APPROVED_EXCERPT)


def test_manual_answer_requires_text():
    with pytest.raises(ValueError):
        ApprovalDecision(outcome=Outcome.MANUAL_ANSWER)
