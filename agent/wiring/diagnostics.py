# Shared diagnostic checks, used by BOTH `callsign signal` (cli.py) and
# the `callsign_signal` MCP tool (mcp_server.py) — moved here from
# cli.py (where they originally lived as CLI-only helpers for `callsign
# setup`/`callsign mynumber`/`callsign switchboard`) so neither surface
# reimplements the other's checks. Pure move for the four pre-existing
# functions; only run_diagnostics() and the mcp-config-path check are
# new.

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import httpx

from .local_state import LocalIdentity
from .registry_client import RegistryClient

UNREACHABLE = "unreachable"


def registry_reachable(registry_url: str) -> bool:
    """Not just "something answers" — an unrelated FastAPI backend on the
    same port could also 404 a made-up route. Confirm it's actually Relay
    via the OpenAPI title FastAPI(title="Relay Registry") sets in
    registry/app.py."""
    try:
        response = httpx.get(f"{registry_url.rstrip('/')}/openapi.json", timeout=2.0)
        return response.status_code == 200 and response.json().get("info", {}).get("title") == "Relay Registry"
    except httpx.HTTPError:
        return False


def pid_alive_from_file(pid_file: Path) -> int | None:
    """PID from a pidfile, but only if that process is actually alive —
    a stale pidfile from a killed/crashed process must not be reported as
    running."""
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
    except ValueError:
        return None
    try:
        os.kill(pid, 0)  # signal 0: existence check only, doesn't actually signal
    except ProcessLookupError:
        return None
    except PermissionError:
        return pid  # exists, just owned by someone else — still "running"
    return pid


def registered_pubkey(registry_url: str, handle: str) -> str | None | object:
    """Same check `callsign setup` relies on (RegistryClient.get_identity
    -> None on 404) — reused here, not duplicated.

    Returns the registered pubkey hex, None if the handle isn't
    registered, or the UNREACHABLE sentinel if the registry can't be
    reached at all — distinct from "verified as mismatched", must never
    be conflated with either."""
    try:
        registry = RegistryClient.create(registry_url)
        identity_row = registry.get_identity(handle)
    except httpx.HTTPError:
        return UNREACHABLE
    return identity_row["public_key_hex"] if identity_row else None


@dataclass
class DiagnosticResult:
    name: str
    passed: bool
    detail: str
    fix: str = ""


def run_diagnostics(
    config: dict,
    serve_pid_file: Path,
    mcp_config_path: Path | None = None,
) -> list[DiagnosticResult]:
    """One shared diagnostic function — `callsign signal` and
    `callsign_signal` both call this and only format the output
    differently. config needs "registry_url", "handle", "key_dir"."""
    results: list[DiagnosticResult] = []

    registry_url = config["registry_url"]
    reachable = registry_reachable(registry_url)
    results.append(
        DiagnosticResult(
            "registry_reachable",
            reachable,
            registry_url,
            fix="" if reachable else "Check network connectivity, or the registry may be down.",
        )
    )

    handle = config.get("handle", "")
    pubkey = registered_pubkey(registry_url, handle) if handle else None
    if not handle:
        results.append(DiagnosticResult("identity_registered", False, "no handle configured", fix="Run `callsign setup`."))
    elif pubkey is UNREACHABLE:
        results.append(
            DiagnosticResult("identity_registered", False, "cannot verify — registry unreachable", fix="")
        )
    else:
        results.append(
            DiagnosticResult(
                "identity_registered",
                pubkey is not None,
                f"@{handle}" if pubkey is not None else f"@{handle} not registered",
                fix="" if pubkey is not None else "Run `callsign setup`.",
            )
        )

    key_dir = config.get("key_dir")
    if pubkey is not None and pubkey is not UNREACHABLE and key_dir and handle:
        try:
            local_identity = LocalIdentity.load_or_create(handle, key_dir)
            local_pubkey = local_identity.public_key_hex
        except Exception:
            local_pubkey = None
        matches = local_pubkey == pubkey if local_pubkey else False
        results.append(
            DiagnosticResult(
                "local_key_matches_registered",
                matches,
                f"key_dir={key_dir}",
                fix=(
                    ""
                    if matches
                    else "Local key doesn't match what's registered. Run `callsign mynumber` to confirm, "
                    "then `callsign setup --force`."
                ),
            )
        )

    listener_pid = pid_alive_from_file(serve_pid_file)
    results.append(
        DiagnosticResult(
            "listener_running",
            listener_pid is not None,
            f"pid={listener_pid}" if listener_pid else str(serve_pid_file),
            fix="" if listener_pid is not None else "Run `callsign standby` (or call `callsign_setup`) to start the listener.",
        )
    )

    if mcp_config_path is not None:
        if not mcp_config_path.exists():
            results.append(
                DiagnosticResult(
                    "mcp_config_paths_match",
                    False,
                    f"{mcp_config_path} does not exist",
                    fix="Run `callsign connect`.",
                )
            )
        else:
            try:
                mcp_config = json.loads(mcp_config_path.read_text())
                env = mcp_config.get("mcpServers", {}).get("callsign", {}).get("env", {})
                mismatches = []
                for field, key in (("key_dir", "CALLSIGN_KEY_DIR"), ("capsule_dir", "CALLSIGN_CAPSULE_DIR"),
                                    ("handle", "CALLSIGN_HANDLE"), ("registry_url", "CALLSIGN_REGISTRY_URL")):
                    if config.get(field) and env.get(key) and config[field] != env[key]:
                        mismatches.append(key)
                results.append(
                    DiagnosticResult(
                        "mcp_config_paths_match",
                        not mismatches,
                        f"{mcp_config_path}" if not mismatches else f"drifted fields: {mismatches}",
                        fix="" if not mismatches else "Run `callsign connect` to repair.",
                    )
                )
            except (json.JSONDecodeError, KeyError):
                results.append(
                    DiagnosticResult(
                        "mcp_config_paths_match", False, f"{mcp_config_path} is malformed",
                        fix="Run `callsign connect` to rewrite it.",
                    )
                )

    return results
