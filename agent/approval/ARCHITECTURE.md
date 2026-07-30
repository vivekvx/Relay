# agent/approval — architecture

Terminal approval UI. Pure function of (ApprovalRequest, a capsule lookup
dict) → (ApprovalDecision, optional GrantPromotion). No network, no
persistence, no candidate search, no capsule loading — all out of scope
here (PRD.md §3.2).

## Built against real resolver types — no stand-ins

`types.py` imports `ApprovalRequest`, `ApprovalState`, and `Capsule`
directly from `resolver.types`. It does not redefine them. This module's
tests (`tests/test_approval.py`) import `ApprovalRequest`/`Capsule` from
`resolver.types` as well, not from `approval`, specifically to prove real
integration rather than two parallel definitions that happen to look alike.

`ApprovalRequest.candidate_capsule_ids` is `tuple[str, ...]` — bare capsule
IDs. `resolve_approval`'s second argument is `capsules_by_id: dict[str,
Capsule]`, the same shape `resolver.resolve_scope` already takes — this
module looks candidates up in it rather than receiving pre-hydrated Capsule
objects, matching the calling convention resolver itself established.

## Match-reason and suggested-span (closed)

`resolver.search_candidates` returns `tuple[SearchCandidate, ...]`: each
result carries the capsule ID plus `match_reason` (which keyword(s)
matched content, or which tag(s) matched) and an optional `relevant_span`
(a content offset pair; `None` for a tag-only match — an expected case,
not an exceptional one). PRD.md §3.2's "one-line summary of why each was
matched" and §8's "pre-highlight the relevant span" are both satisfied
upstream now.

This module consumes it via an optional `match_info: dict[str,
SearchCandidate] | None` parameter, keyed by capsule ID — a caller with no
search results (or exercising the old flow) simply omits it, and behavior
is unchanged from before this gap closed:

- `render.render_request` prints a `why matched: ...` line under a
  candidate only when `match_info` supplies one for that capsule.
- `interaction._approve_excerpt` offers `"Use suggested span
  {start},{end}? [Y/n]: "` only when `match_info` has a `relevant_span`
  for the chosen capsule; declining ("n"/"no") or `match_info` lacking a
  span falls through to the unchanged manual `"Enter span as
  'start,end': "` prompt. Any other answer is ambiguous -> deny, same
  default-safe rule as every other prompt here.

`types.py`'s `ApprovalDecision`/`ExcerptBounds` contract did not need to
change — the new data flows through as an extra rendering/prompt input,
not a new decision shape.

Not wired end-to-end yet: `wiring/flows.py` still only threads bare
capsule IDs into `ApprovalRequest.candidate_capsule_ids` and does not
build/pass a `match_info` map into the live terminal prompt — that's
future work, not part of this task's scope.

## Default-safe-on-ambiguity invariant

Any input that is invalid, ambiguous, unrecognized, or interrupted (Ctrl+C,
Ctrl+D/EOF) resolves to `Outcome.DENIED` — never to an approved outcome.
This is the human-input-layer instance of PRD.md §5 R5 / CLAUDE.md §2's
"unresolved must never silently grant" rule.

Enforced structurally in `interaction.py`: every parsing branch in
`_approve_whole`/`_approve_excerpt`/`_manual_answer` that isn't a fully
valid, in-range choice falls through to `_denied()`. `_read()` centralizes
the EOFError/KeyboardInterrupt → `None` → deny path so no individual prompt
can accidentally treat an interrupt as empty input and continue. No retry
loop exists on purpose — one bad input ends the flow denied, so there's no
path where repeated fuzzing eventually stumbles into approval.

Already-expired requests (`request.state is ApprovalState.EXPIRED`, or
`now >= request.expires_at`) short-circuit before any prompt is rendered or
any question asked — see
`test_already_expired_request_short_circuits_without_prompting`. This does
not implement expiry *policy* (deciding whether a request has expired is
the registry's on-read check, out of scope here); it only refuses to act as
though an already-past-deadline request were still live. Note
`resolver.types.ApprovalRequest.resolved_state()` maps a timed-out PENDING
request to `ApprovalState.DENIED`, not `EXPIRED` — this module's own
`Outcome.EXPIRED` is a separate, finer-grained value (see below) and is not
meant to mirror that resolver-side auto-deny mapping 1:1.

## Decision object contract (for the next task — MCP server wiring)

`request_approval(request, capsules_by_id, input_fn=, output_fn=, now=) ->
ApprovalDecision`

`ApprovalDecision.outcome` is one of (`approval.types.Outcome`, distinct
from `resolver.types.ApprovalState` — the resolver only needs
pending/approved/denied/expired for grant bookkeeping, this module needs to
preserve *how* it was approved):

- `APPROVED_WHOLE` — `approved_capsule_ids: tuple[str, ...]` populated,
  release each capsule's full content.
- `APPROVED_EXCERPT` — `excerpt: ExcerptBounds` populated
  (`capsule_id`, `start`, `end`); release only `content[start:end]` of that
  one capsule.
- `DENIED` — release nothing.
- `MANUAL_ANSWER` — `manual_answer: str` populated; release only that text,
  no capsule content leaves the machine.
- `EXPIRED` — release nothing; the request was already past its deadline
  and no human was asked anything.

`__post_init__` raises `ValueError` if a decision is constructed with the
wrong fields for its outcome (e.g. `APPROVED_WHOLE` with no capsule ids) —
this catches a caller-side bug before it reaches persistence.

`request_grant_promotion(decision, request, capsules_by_id, input_fn=,
output_fn=) -> GrantPromotion | None` is a **separate call**, made only
after `request_approval` returns (approve or deny — never after
`MANUAL_ANSWER` or `EXPIRED`, since neither of those disclosed any capsule
scope worth promoting into a standing grant). `GrantPromotion` and
`ApprovalDecision` share no fields (see
`test_grant_promotion_type_has_no_overlap_with_approval_decision_fields`) —
a caller cannot mistake "I approved this request" for "I created a standing
grant." Recording the promotion as an actual `resolver.types.Grant` is the
next task's job; this module only returns the intent
(`grantee_handle`/`scope_description`/`capsule_ids`).

Neither function persists, sends, or logs anything. The caller (a later
MCP-server task) owns writing the decision to the registry/audit log and
turning an accepted `GrantPromotion` into a real `resolver.types.Grant`.
