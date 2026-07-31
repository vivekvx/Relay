# Shared local-JSON-store primitives used by threads.py,
# disclosure_log.py, pending_approvals.py, and contacts.py — one
# implementation, not four. Fixes two distinct problems:
#
# 1. Torn writes: plain `open(path, "w") + json.dump` is not atomic — a
#    crash mid-write (or a concurrent read at the wrong instant) can see
#    a truncated/partial file. atomic_write_json() writes to a temp file
#    in the SAME directory (so the final os.replace is on the same
#    filesystem, which is what makes it atomic), fsyncs it, then
#    os.replace()s over the target — any reader/crash at any point sees
#    either the complete old file or the complete new one, never a torn
#    one.
#
# 2. Cross-process lost updates: atomicity alone does NOT fix two
#    processes racing — `relay serve`'s long-lived background poll loop
#    and a concurrent manual `relay ask`/`relay pending`/`relay
#    contacts` invocation are a REAL scenario, not a hypothetical one,
#    since headless serve mode exists specifically so a person keeps
#    using the CLI normally while it runs. If both read the file into
#    memory, mutate their own in-memory copy, and write back
#    independently, the second writer's save silently clobbers the
#    first's change — atomic writes make each individual write clean,
#    but do nothing to stop one clean write from overwriting another.
#    `locked()` is a POSIX advisory exclusive lock (fcntl.flock) on a
#    `.lock` sidecar file, held for the caller's ENTIRE
#    read-modify-write critical section (re-read from disk, mutate,
#    write back), not just the final write step — this is what actually
#    closes the lost-update race. POSIX-only (fcntl), consistent with
#    this project's existing Unix-first stance (identity/'s key-storage
#    permission handling already refuses non-Unix rather than silently
#    behaving differently).

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from typing import Any


def atomic_write_json(path: str, data: Any) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


@contextlib.contextmanager
def locked(path: str):
    """Held for the caller's entire read-modify-write critical section —
    see module docstring for why atomicity alone isn't enough. Callers
    re-read fresh state from disk INSIDE this context, mutate, and write
    back INSIDE this context, before it exits."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = path + ".lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
