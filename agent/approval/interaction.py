# Input capture for the terminal approval prompt.
#
# INVARIANT (do not weaken): any invalid, ambiguous, interrupted, or
# unrecognized input MUST resolve to Outcome.DENIED. Never guess, never
# default to approval. This is the human-input-layer instance of the
# "unresolved must never silently grant" rule (PRD.md §5 R5, CLAUDE.md §2).
# Every return path below that isn't a fully-parsed, in-range, well-formed
# choice goes through _denied().

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from resolver.types import SearchCandidate

from .render import render_excerpt_view, render_request
from .types import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalState,
    Capsule,
    ExcerptBounds,
    GrantPromotion,
    Outcome,
)

InputFn = Callable[[str], str]
OutputFn = Callable[[str], None]


def _denied(now: datetime) -> ApprovalDecision:
    return ApprovalDecision(outcome=Outcome.DENIED, decided_at=now)


def _read(input_fn: InputFn, prompt: str) -> str | None:
    # Ctrl+C / Ctrl+D / EOF during any prompt -> None, which every call site
    # below treats as "abort to denied", never as "treat as empty and
    # continue".
    try:
        return input_fn(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def _resolve_candidates(request: ApprovalRequest, capsules_by_id: dict[str, Capsule]) -> list[Capsule]:
    # A candidate id with no matching capsule (deleted/revoked since the
    # request was created) is silently dropped from the displayed list
    # rather than crashing the prompt — the approver simply can't select
    # something that no longer exists.
    return [capsules_by_id[cid] for cid in request.candidate_capsule_ids if cid in capsules_by_id]


def request_approval(
    request: ApprovalRequest,
    capsules_by_id: dict[str, Capsule],
    *,
    input_fn: InputFn = input,
    output_fn: OutputFn = print,
    now: datetime | None = None,
    match_info: dict[str, SearchCandidate] | None = None,
) -> ApprovalDecision:
    now = now or datetime.now(timezone.utc)

    # Already-expired requests are refused outright: no prompt rendered, no
    # question asked. This does not decide expiry policy (that's the
    # registry's on-read check, out of scope here) — it only refuses to act
    # as if a request past its own expires_at were still live.
    if request.state is ApprovalState.EXPIRED or now >= request.expires_at:
        return ApprovalDecision(outcome=Outcome.EXPIRED, decided_at=now)

    candidates = _resolve_candidates(request, capsules_by_id)

    output_fn(render_request(request, candidates, now=now, match_info=match_info))
    choice = _read(input_fn, "> ")
    if choice is None:
        return _denied(now)
    choice = choice.strip().lower()

    if choice in ("w", "whole"):
        return _approve_whole(candidates, input_fn, now)
    if choice in ("e", "excerpt"):
        return _approve_excerpt(candidates, input_fn, output_fn, now, match_info=match_info)
    if choice in ("m", "manual"):
        return _manual_answer(input_fn, now)
    if choice in ("d", "deny"):
        return _denied(now)

    return _denied(now)  # unrecognized choice: ambiguous -> deny


def _approve_whole(candidates: list[Capsule], input_fn: InputFn, now: datetime) -> ApprovalDecision:
    raw = _read(input_fn, "Which document(s)? (enter the number, e.g. 1 or 1,2): ")
    if raw is None:
        return _denied(now)

    picks: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part.isdigit():
            return _denied(now)
        idx = int(part)
        if not (1 <= idx <= len(candidates)):
            return _denied(now)
        picks.append(idx)
    if not picks:
        return _denied(now)

    ids = tuple(candidates[i - 1].id for i in picks)
    return ApprovalDecision(outcome=Outcome.APPROVED_WHOLE, approved_capsule_ids=ids, decided_at=now)


def _approve_excerpt(
    candidates: list[Capsule],
    input_fn: InputFn,
    output_fn: OutputFn,
    now: datetime,
    match_info: dict[str, SearchCandidate] | None = None,
) -> ApprovalDecision:
    raw = _read(input_fn, "Which document? (enter the number): ")
    if raw is None or not raw.strip().isdigit():
        return _denied(now)
    idx = int(raw.strip())
    if not (1 <= idx <= len(candidates)):
        return _denied(now)

    capsule = candidates[idx - 1]
    output_fn(render_excerpt_view(capsule))

    # Suggested-span confirm shortcut: only offered when resolver actually
    # supplied a relevant_span for this capsule. Any answer other than a
    # clear yes/no ("", y, yes / n, no) is ambiguous -> deny, same
    # default-safe rule as every other prompt here. Declining ("n"/"no")
    # falls through to manual bound entry below, unchanged.
    match = match_info.get(capsule.id) if match_info else None
    if match is not None and match.relevant_span is not None:
        span_start, span_end = match.relevant_span
        raw_confirm = _read(input_fn, f"Share just the matched part ({span_start}-{span_end})? [Y/n]: ")
        if raw_confirm is None:
            return _denied(now)
        answer = raw_confirm.strip().lower()
        if answer in ("", "y", "yes"):
            content_len = len(capsule.content)
            if not (0 <= span_start < span_end <= content_len):
                return _denied(now)
            bounds = ExcerptBounds(capsule_id=capsule.id, start=span_start, end=span_end)
            return ApprovalDecision(outcome=Outcome.APPROVED_EXCERPT, excerpt=bounds, decided_at=now)
        if answer not in ("n", "no"):
            return _denied(now)

    raw_bounds = _read(input_fn, "Which part? (enter as start,end character positions, e.g. 0,120): ")
    if raw_bounds is None:
        return _denied(now)
    parts = raw_bounds.strip().split(",")
    if len(parts) != 2 or not all(p.strip().lstrip("-").isdigit() for p in parts):
        return _denied(now)
    start, end = int(parts[0]), int(parts[1])

    content_len = len(capsule.content)
    if not (0 <= start < end <= content_len):
        return _denied(now)

    bounds = ExcerptBounds(capsule_id=capsule.id, start=start, end=end)
    return ApprovalDecision(outcome=Outcome.APPROVED_EXCERPT, excerpt=bounds, decided_at=now)


def _manual_answer(input_fn: InputFn, now: datetime) -> ApprovalDecision:
    raw = _read(input_fn, "Type your answer: ")
    if raw is None or not raw.strip():
        return _denied(now)
    return ApprovalDecision(outcome=Outcome.MANUAL_ANSWER, manual_answer=raw.strip(), decided_at=now)


def request_grant_promotion(
    decision: ApprovalDecision,
    request: ApprovalRequest,
    capsules_by_id: dict[str, Capsule],
    *,
    input_fn: InputFn = input,
    output_fn: OutputFn = print,
) -> GrantPromotion | None:
    # Only offered after a real, completed decision - never after EXPIRED
    # (nothing was decided) and never after MANUAL_ANSWER (no capsule was
    # involved, so there is nothing capsule-shaped to promote into a grant).
    if decision.outcome not in (Outcome.APPROVED_WHOLE, Outcome.APPROVED_EXCERPT, Outcome.DENIED):
        return None

    raw = _read(
        input_fn,
        f"Let @{request.sender} skip approval for this topic in future? [y/N]: ",
    )
    if raw is None or raw.strip().lower() != "y":
        return None

    if decision.outcome is Outcome.APPROVED_WHOLE:
        capsule_ids = decision.approved_capsule_ids
    elif decision.outcome is Outcome.APPROVED_EXCERPT:
        capsule_ids = (decision.excerpt.capsule_id,)
    else:  # DENIED — promoting a denial means "never ask again for this scope"
        capsule_ids = tuple(c.id for c in _resolve_candidates(request, capsules_by_id))

    scope = _read(input_fn, "Describe the scope to grant (e.g. topic name): ")
    if scope is None or not scope.strip():
        return None

    return GrantPromotion(
        grantee_handle=request.sender,
        scope_description=scope.strip(),
        capsule_ids=capsule_ids,
    )
