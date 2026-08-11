# Shared local-state path constants. Moved out of cli.py so both cli.py
# and mcp_server.py import the same values from wiring/ rather than one
# importing from the other (mcp_server.py must not depend on cli.py —
# wrong dependency direction, cli.py is the CLI entrypoint, not a
# library).

import shutil
from pathlib import Path

REGISTRY_HOME = Path.home() / ".callsign"
LEGACY_RELAY_HOME = Path.home() / ".relay"  # pre-rename home dir — read-only, see migrate_from_relay_if_needed
SERVE_PID_FILE = REGISTRY_HOME / "serve.pid"
SERVE_META_FILE = REGISTRY_HOME / "serve.json"  # {"pid": ..., "started_at": isoformat}
SERVE_LOG_FILE = REGISTRY_HOME / "serve.log"

# Everything a pre-rename ~/.relay might hold that's worth carrying
# forward. Not every entry exists on every install (e.g. contacts.json
# is a newer feature) — migrate_from_relay_if_needed skips whatever's
# missing rather than failing.
_MIGRATABLE_ENTRIES = (
    "config.toml", "keys", "capsules", "threads.json", "disclosure_log.json",
    "pending_approvals.json", "contacts.json",
)


def migrate_from_relay_if_needed(
    relay_home: Path = LEGACY_RELAY_HOME, callsign_home: Path = REGISTRY_HOME
) -> bool:
    """One-time migration for the Relay -> Callsign rename: if
    ~/.callsign doesn't exist yet but ~/.relay does, copy config.toml,
    keys/, capsules/, and the rest of _MIGRATABLE_ENTRIES across. Never
    deletes or modifies ~/.relay — it's left in place untouched; this
    only makes callsign commands stop reading from it going forward.

    Returns True iff a migration actually ran (so callers can print a
    one-time notice). A no-op (nothing to migrate, or already migrated)
    returns False."""
    if callsign_home.exists() or not relay_home.exists():
        return False
    callsign_home.mkdir(parents=True, exist_ok=True)
    for name in _MIGRATABLE_ENTRIES:
        src = relay_home / name
        if not src.exists():
            continue
        dst = callsign_home / name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
    return True
