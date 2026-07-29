# Pure rendering: builds display strings only, no IO. Kept separate from
# interaction.py so the prompt layout is testable without stdin/stdout.
#
# No "why matched" line and no pre-highlighted span: resolver.search_candidates
# returns bare capsule IDs only (no score, no matched keywords, no span) — see
# ARCHITECTURE.md "Known upstream gap". This renders only what candidates
# actually carry (id, tags, content); it does not synthesize a reason or a
# span that resolver never produced.

from __future__ import annotations

from datetime import datetime, timezone

from .types import ApprovalRequest, Capsule


def format_time_remaining(request: ApprovalRequest, *, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    remaining = request.expires_at - now
    seconds = int(remaining.total_seconds())
    if seconds <= 0:
        return "expired"
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    return f"{hours}h {minutes}m"


def render_request(
    request: ApprovalRequest,
    candidates: list[Capsule],
    *,
    now: datetime | None = None,
) -> str:
    lines = [
        f"Request from {request.sender}",
        f'  "{request.query}"',
        f"Expires in: {format_time_remaining(request, now=now)}",
        "",
        "Candidate documents:",
    ]
    for i, capsule in enumerate(candidates, start=1):
        tags = ", ".join(sorted(capsule.tags)) or "(no tags)"
        lines.append(f"  [{i}] {capsule.id} — tags: {tags}")
    lines += [
        "",
        "Choose: (w)hole doc(s) / (e)xcerpt / (d)eny / (m)anual answer",
    ]
    return "\n".join(lines)


def render_excerpt_view(capsule: Capsule) -> str:
    # No span markers: resolver never supplies a relevant_span, so there is
    # nothing to highlight — just the full content the approver must bound
    # manually.
    return capsule.content
