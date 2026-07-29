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

from .types import Capsule, Grant, SenderIdentity


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


def search_candidates(
    sender: SenderIdentity,
    query: str,
    capsules: list[Capsule],
    limit: int = 5,
) -> tuple[str, ...]:
    """Deterministic keyword matching against capsule metadata/content —
    never LLM-selected (PRD.md §5 R8). Surfaces candidates for the
    approver's decision only; it grants nothing by itself.

    # ponytail: in-memory keyword scoring, not real SQLite FTS5 — FTS5
    # indexing is a agent/capsules/ concern (out of scope for this task).
    # Swap this scoring for an FTS5 query later without changing the
    # determinism contract: same inputs must always produce the same
    # ranked output.
    """
    keywords = set(_tokenize(query))
    scored: list[tuple[int, str]] = []
    for capsule in capsules:
        if not capsule.shareable:
            continue
        if capsule.shareable_with and sender.handle not in capsule.shareable_with:
            continue
        haystack = _tokenize(capsule.content + " " + " ".join(capsule.tags))
        score = sum(haystack.count(k) for k in keywords)
        if score > 0:
            scored.append((score, capsule.id))
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    return tuple(cid for _, cid in scored[:limit])
