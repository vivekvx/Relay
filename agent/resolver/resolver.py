# THE deterministic scope-resolution component. PRD.md §5 R1, R7, R8;
# CLAUDE.md §2 (non-negotiable invariants). MUST NEVER invoke an LLM.
#
# `resolve_scope` intentionally does not take the query text as an
# input at all — it cannot be influenced by query content by
# construction, which is the strongest possible guarantee against R1
# (direct prompt injection). Only sender identity and grant state
# affect the result.

from __future__ import annotations

import re
from datetime import datetime, timedelta

from .types import Capsule, Grant, SearchCandidate, SenderIdentity


def resolve_scope(
    sender: SenderIdentity,
    grants: list[Grant],
    capsules_by_id: dict[str, Capsule],
    now: datetime,
) -> frozenset[str]:
    """Return the exact set of capsule IDs permitted to load into an LLM's
    context for this sender, right now. Re-validates every grant at call
    time (§3.1 step 8) — a revoked grant contributes nothing, even if it
    was valid when the request was first received."""
    resolved: set[str] = set()
    for grant in grants:
        if grant.grantee != sender.handle:
            continue
        if not grant.is_valid(now):
            continue
        resolved |= {cid for cid in grant.capsule_ids if cid in capsules_by_id}
    return frozenset(resolved)


_WORD_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def _find_span(content: str, keyword: str) -> tuple[int, int] | None:
    # First occurrence only — enough to point an approver at the matched
    # region; deterministic (same content+keyword always finds the same
    # span), never dependent on match count or ordering elsewhere.
    match = re.search(rf"\b{re.escape(keyword)}\b", content, re.IGNORECASE)
    return (match.start(), match.end()) if match else None


def search_candidates(
    sender: SenderIdentity,
    query: str,
    capsules: list[Capsule],
    limit: int = 5,
) -> tuple[SearchCandidate, ...]:
    """Deterministic keyword matching against capsule metadata/content —
    never LLM-selected (PRD.md §5 R8). Surfaces candidates for the
    approver's decision only; it grants nothing by itself.

    Each result carries a `match_reason` (which keyword(s) matched
    content, or which tag(s) matched) and, when the match traces to a
    specific content region, a `relevant_span` — None for a tag-only
    match, which is an expected case, not an exceptional one.

    # ponytail: in-memory keyword scoring, not real SQLite FTS5 — FTS5
    # indexing is a agent/capsules/ concern (out of scope for this task).
    # Swap this scoring for an FTS5 query later without changing the
    # determinism contract: same inputs must always produce the same
    # ranked output.
    """
    keywords = sorted(set(_tokenize(query)))
    scored: list[tuple[int, str, str, tuple[int, int] | None]] = []
    for capsule in capsules:
        if not capsule.shareable:
            continue
        if capsule.shareable_with and sender.handle not in capsule.shareable_with:
            continue
        content_tokens = _tokenize(capsule.content)
        tag_tokens = {tok for tag in capsule.tags for tok in _tokenize(tag)}

        content_matches = [k for k in keywords if k in content_tokens]
        tag_matches = [k for k in keywords if k in tag_tokens]
        score = sum(content_tokens.count(k) for k in content_matches) + len(tag_matches)
        if score == 0:
            continue

        if content_matches:
            reason = f"keyword match: {', '.join(content_matches)}"
            span = _find_span(capsule.content, content_matches[0])
        else:
            reason = f"tag match: {', '.join(tag_matches)}"
            span = None
        scored.append((score, capsule.id, reason, span))

    scored.sort(key=lambda t: (-t[0], t[1]))
    return tuple(
        SearchCandidate(capsule_id=cid, match_reason=reason, relevant_span=span)
        for _, cid, reason, span in scored[:limit]
    )


def split_thread_candidates(
    candidate_ids: tuple[str, ...],
    approved_capsule_ids: frozenset[str],
) -> tuple[tuple[str, ...], frozenset[str]]:
    """Deterministic thread-continuation check (no LLM, no query-content
    involvement) — the only test for "does this follow-up need a fresh
    approval prompt": is every candidate this query surfaced already in
    the conversation's approved-scope-set?

    Returns (new_candidate_ids, reusable_capsule_ids). `new_candidate_ids`
    is what must go through request_approval (only the unapproved ones —
    never re-prompting for a capsule already consented to in this thread).
    `reusable_capsule_ids` is the subset of candidates already approved,
    safe to answer from immediately. Same-scope follow-up (spec's CASE A)
    is exactly "new_candidate_ids is empty and reusable_capsule_ids is
    not"; new-scope follow-up (CASE B) is "new_candidate_ids is
    non-empty" — every conversation-aware caller decides its branch from
    these two return values alone, never from comparing query text."""
    new_ids = tuple(cid for cid in candidate_ids if cid not in approved_capsule_ids)
    reusable = frozenset(candidate_ids) & approved_capsule_ids
    return new_ids, reusable


# ---------------------------------------------------------------------
# Anti-enumeration guard (PRD.md §5 R3 "salami slicing") — deterministic
# math only, no LLM, no query content involved. Advisory, not blocking:
# the human approver still decides; this only tells them whether the
# sender's cumulative footprint against their capsule library looks
# broad. See agent/ARCHITECTURE.md "Anti-enumeration guard" for the
# exact formula and default thresholds.
# ---------------------------------------------------------------------

DEFAULT_ENUMERATION_WINDOW = timedelta(days=30)
DEFAULT_ENUMERATION_FRACTION_THRESHOLD = 0.4  # >40% of the recipient's capsules
DEFAULT_ENUMERATION_ABSOLUTE_THRESHOLD = 15  # or >15 distinct capsules, whichever fires first


def enumeration_flag(
    distinct_capsules_seen: int,
    total_capsule_count: int,
    *,
    fraction_threshold: float = DEFAULT_ENUMERATION_FRACTION_THRESHOLD,
    absolute_threshold: int = DEFAULT_ENUMERATION_ABSOLUTE_THRESHOLD,
) -> bool:
    """True if a sender's cumulative distinct-capsules-seen count (within
    whatever rolling window the caller already restricted it to) exceeds
    EITHER the fraction of the recipient's total capsule library OR the
    absolute count — whichever is more restrictive, i.e. either
    condition alone is enough to flag. `total_capsule_count == 0` never
    flags (nothing to enumerate)."""
    if total_capsule_count <= 0:
        return False
    exceeds_fraction = (distinct_capsules_seen / total_capsule_count) > fraction_threshold
    exceeds_absolute = distinct_capsules_seen > absolute_threshold
    return exceeds_fraction or exceeds_absolute
