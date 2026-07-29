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

## Known upstream gap: no match-reason or span data

`resolver.search_candidates` (as it actually exists — verified by reading
`resolver/resolver.py`) returns `tuple[str, ...]`: bare capsule IDs, no
score, no matched-keyword list, no relevant span. PRD.md §3.2 asks for "a
one-line summary of why each was matched" and §8 asks for the resolver to
"pre-highlight the relevant span" before excerpt approval. Neither exists
in the current implementation.

Per explicit instruction, this module does **not** invent a reason string
or a fake span to paper over the gap. Concretely:

- `render.render_request` lists each candidate as `[n] capsule_id — tags:
  ...` — no "why matched" line, because there's nothing upstream to draw
  one from.
- `interaction._approve_excerpt` always prompts `"Enter span as
  'start,end': "` — there is no "confirm the suggested span" shortcut,
  because `relevant_span` never exists to confirm.

Closing this gap means extending `resolver.search_candidates` to return
per-candidate score/reason/span (e.g. richer than a bare ID tuple) — that's
a resolver-side change, out of scope for this task. When it happens, only
`render.py`/`interaction.py`'s candidate-list and excerpt-view rendering
need to change; `types.py`'s `ApprovalDecision`/`ExcerptBounds` contract
does not.

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
