# Pure rendering: builds display strings only, no IO. Kept separate from
# interaction.py so the prompt layout is testable without stdin/stdout.
#
# match_info is optional and keyed by capsule ID (resolver.SearchCandidate
# per ID) — callers that don't have search results simply omit it, and
# rendering falls back to the old no-match-reason behavior unchanged.

from __future__ import annotations

from datetime import datetime, timezone

from resolver.types import SearchCandidate

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
    match_info: dict[str, SearchCandidate] | None = None,
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
        match = match_info.get(capsule.id) if match_info else None
        if match is not None:
            lines.append(f"      why matched: {match.match_reason}")
    lines += [
        "",
        "Choose: (w)hole doc(s) / (e)xcerpt / (d)eny / (m)anual answer",
    ]
    return "\n".join(lines)


def render_excerpt_view(capsule: Capsule) -> str:
    # No span markers here: highlighting the suggested span is the
    # interaction.py prompt's job (the "confirm suggested span" shortcut) —
    # this stays a plain content dump so it works identically whether or
    # not a relevant_span exists upstream.
    return capsule.content
