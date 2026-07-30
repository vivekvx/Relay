# macOS-only native notification for a new queued ad hoc approval
# request, fired from `relay serve` (headless — no visible terminal to
# show the live prompt on). Deliberately just `osascript` (stdlib
# subprocess, ships with macOS, zero new dependency) — this task's
# explicit scope excludes any external push service.
#
# Known limitation, stated plainly rather than left as a silent gap:
# clicking this notification does NOT open a terminal with the live
# prompt pre-filled in this pass — `display notification` (unlike
# `display alert`/a `terminal-notifier -execute` setup) has no click
# action available through plain AppleScript. The documented, fully
# working fallback is `relay pending`, which prints its own name in the
# notification body for exactly this reason.

from __future__ import annotations

import subprocess


def _applescript_string_literal(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def notify_new_approval_request(sender: str, query: str) -> bool:
    """Best-effort: returns True if osascript accepted the notification,
    False otherwise (non-macOS, osascript missing, or it errored) —
    never raises. A failed notification must never block or fail the
    poll loop that's delivering real requests; `relay pending` remains
    the reliable way to discover queued requests regardless of whether
    this fired."""
    title = _applescript_string_literal(f"Relay: approval request from @{sender}")
    body = _applescript_string_literal(query)
    subtitle = _applescript_string_literal("Run `relay pending` to review and answer")
    script = f"display notification {body} with title {title} subtitle {subtitle}"
    try:
        result = subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
