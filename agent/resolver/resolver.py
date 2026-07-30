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
from datetime import datetime

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
