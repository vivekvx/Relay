# Non-interactive setup + listener-autostart logic, shared by the CLI
# (`relay init`/`relay register`/`relay serve`) and the new `relay_setup`
# MCP tool — an MCP tool call has no terminal to prompt on, so this
# module only ever does the non-interactive path cmd_init/cmd_register
# already support via --non-interactive/--force; the interactive
# prompt/confirm layer stays in cli.py.
#
# Idempotent by construction: re-calling ensure_setup with the same
# config just rewrites the same TOML content and hits the registry's
# existing 409-swallow-on-reregister behavior; re-calling
# ensure_listener_running with an already-alive pidfile no-ops (same
# pidfile-liveness check cmd_serve already used before this extraction).

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .diagnostics import UNREACHABLE, pid_alive_from_file, registered_pubkey
from .local_state import LocalIdentity
from .registry_client import RegistryClient, RegistryRejection


@dataclass
class SetupResult:
    handle: str
    already_configured: bool
    already_registered: bool
    relay_number: str | None = None
    warnings: list[str] = field(default_factory=list)


def _write_config_toml(config_path: Path, config: dict) -> None:
    """Same TOML shape cli.py's _write_config already produces — kept
    identical so `relay init`/`relay_setup` write byte-compatible files."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text("".join(f'{k} = "{v}"\n' for k, v in config.items()))


def ensure_setup(
    handle: str,
    capsule_dir: str,
    registry_url: str,
    key_dir: str,
    config_path: Path,
    force: bool = False,
) -> SetupResult:
    """Idempotent: safe to call every time relay_setup fires, including
    on every MCP reconnect. Non-interactive equivalent of cmd_init +
    cmd_register chained: writes config (if missing or --force), then
    registers (or reports already-registered via the existing 409-swallow
    pattern)."""
    warnings: list[str] = []
    already_configured = config_path.exists()

    registered = registered_pubkey(registry_url, handle)
    local_identity = LocalIdentity.load_or_create(handle, key_dir)

    if registered not in (UNREACHABLE, None) and registered != local_identity.public_key_hex and not force:
        warnings.append(
            f"@{handle} is already registered with a different key (registered "
            f"{registered[:12]}... vs this key_dir's {local_identity.public_key_hex[:12]}...) "
            f"— pass force=True to proceed anyway."
        )
        return SetupResult(handle=handle, already_configured=already_configured, already_registered=True, warnings=warnings)

    if registered is UNREACHABLE:
        warnings.append(f"couldn't reach {registry_url} to verify prior registration — proceeding unverified.")

    config = {
        "handle": handle,
        "capsule_dir": capsule_dir,
        "key_dir": key_dir,
        "registry_url": registry_url,
        "thread_store": str(config_path.parent / "threads.json"),
        "disclosure_log": str(config_path.parent / "disclosure_log.json"),
        "pending_approvals": str(config_path.parent / "pending_approvals.json"),
        "contacts": str(config_path.parent / "contacts.json"),
    }
    _write_config_toml(config_path, config)

    registry = RegistryClient.create(registry_url)
    relay_number = None
    already_registered = False
    try:
        result = registry.register_identity(handle, local_identity.public_key_hex, local_identity.encryption_public_key_hex)
        relay_number = result["relay_number"]
    except RegistryRejection as e:
        if e.status_code == 409:
            already_registered = True
            own = registry.get_identity(handle)
            relay_number = own["relay_number"] if own else None
        else:
            raise

    return SetupResult(
        handle=handle,
        already_configured=already_configured,
        already_registered=already_registered,
        relay_number=relay_number,
        warnings=warnings,
    )


def ensure_listener_running(
    registry_home: Path,
    serve_pid_file: Path,
    serve_meta_file: Path,
    serve_log_file: Path,
    agent_dir: Path,
    interval: float = 2.0,
    popen_fn=subprocess.Popen,
) -> dict:
    """Extracted from cmd_serve's spawn block, unchanged behavior — the
    single source both `relay serve` and `relay_setup` call, so an
    already-running listener is never double-spawned regardless of which
    surface triggered the check (pidfile-liveness, same pattern as
    serve-registry's detection logic)."""
    pid = pid_alive_from_file(serve_pid_file)
    if pid is not None:
        return {"status": "already_running", "pid": pid}

    registry_home.mkdir(parents=True, exist_ok=True)
    with open(serve_log_file, "a") as log:
        process = popen_fn(
            [sys.executable, "-m", "cli", "listen", "--headless", "--interval", str(interval)],
            cwd=agent_dir,
            env=dict(os.environ),
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    serve_pid_file.write_text(str(process.pid))
    serve_meta_file.write_text(json.dumps({"pid": process.pid, "started_at": datetime.now(timezone.utc).isoformat()}))

    time.sleep(0.5)
    if pid_alive_from_file(serve_pid_file) is not None:
        return {"status": "started", "pid": process.pid}
    return {"status": "failed_to_start", "pid": process.pid}
