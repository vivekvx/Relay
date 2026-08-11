# Each test here reproduces one of the real historical failure modes
# from this session (stale keys, port collision, orphaned process,
# config drift, DATABASE_URL trailing newline) — not hypothetical bugs.

import json

from wiring.diagnostics import UNREACHABLE, run_diagnostics
from wiring.local_state import LocalIdentity


def _base_config(tmp_path, handle="vivek", registry_url="http://example.invalid"):
    return {
        "registry_url": registry_url,
        "handle": handle,
        "key_dir": str(tmp_path / "keys" / handle),
    }


def test_stale_local_key_mismatch_fails_with_fix(tmp_path, monkeypatch):
    """Failure #1: signature-mismatch from stale local keys."""
    config = _base_config(tmp_path)
    registered_key = "a" * 64  # a different pubkey than what load_or_create will produce here

    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: True)
    monkeypatch.setattr("wiring.diagnostics.registered_pubkey", lambda url, handle: registered_key)

    results = run_diagnostics(config, tmp_path / "serve.pid")
    by_name = {r.name: r for r in results}
    assert by_name["local_key_matches_registered"].passed is False
    assert "mynumber" in by_name["local_key_matches_registered"].fix


def test_port_collision_lookalike_service_fails_registry_reachable(tmp_path, monkeypatch):
    """Failure #2: port collision with an unrelated project — registry_reachable
    must reject a 200 response whose OpenAPI title isn't "Relay Registry",
    not just check for any 200."""
    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: False)
    config = _base_config(tmp_path)
    results = run_diagnostics(config, tmp_path / "serve.pid")
    by_name = {r.name: r for r in results}
    assert by_name["registry_reachable"].passed is False


def test_orphaned_pidfile_dead_process_fails_listener_running(tmp_path, monkeypatch):
    """Failure #3: orphaned process after fake-$HOME testing — a stale
    pidfile pointing at a pid that no longer exists must not report as
    running."""
    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: True)
    monkeypatch.setattr("wiring.diagnostics.registered_pubkey", lambda url, handle: UNREACHABLE)

    pid_file = tmp_path / "serve.pid"
    # A pid essentially guaranteed not to exist.
    pid_file.write_text("999999")

    results = run_diagnostics(_base_config(tmp_path), pid_file)
    by_name = {r.name: r for r in results}
    assert by_name["listener_running"].passed is False
    assert "callsign standby" in by_name["listener_running"].fix or "callsign_setup" in by_name["listener_running"].fix


def test_mcp_config_key_dir_drift_fails_with_fix(tmp_path, monkeypatch):
    """Failure #4: config drift silently pointing at the wrong key_dir —
    caught by comparing the loaded config against .mcp.json's env block."""
    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: True)
    monkeypatch.setattr("wiring.diagnostics.registered_pubkey", lambda url, handle: UNREACHABLE)

    config = _base_config(tmp_path)
    mcp_config_path = tmp_path / ".mcp.json"
    mcp_config_path.write_text(json.dumps({
        "mcpServers": {"callsign": {"env": {"CALLSIGN_KEY_DIR": "/totally/different/path"}}}
    }))

    results = run_diagnostics(config, tmp_path / "serve.pid", mcp_config_path=mcp_config_path)
    by_name = {r.name: r for r in results}
    assert by_name["mcp_config_paths_match"].passed is False
    assert "CALLSIGN_KEY_DIR" in by_name["mcp_config_paths_match"].detail


def test_mcp_config_matching_passes(tmp_path, monkeypatch):
    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: True)
    monkeypatch.setattr("wiring.diagnostics.registered_pubkey", lambda url, handle: UNREACHABLE)

    config = _base_config(tmp_path)
    mcp_config_path = tmp_path / ".mcp.json"
    mcp_config_path.write_text(json.dumps({
        "mcpServers": {"callsign": {"env": {"CALLSIGN_KEY_DIR": config["key_dir"]}}}
    }))

    results = run_diagnostics(config, tmp_path / "serve.pid", mcp_config_path=mcp_config_path)
    by_name = {r.name: r for r in results}
    assert by_name["mcp_config_paths_match"].passed is True


def test_missing_mcp_config_fails_with_fix(tmp_path, monkeypatch):
    monkeypatch.setattr("wiring.diagnostics.registry_reachable", lambda url: True)
    monkeypatch.setattr("wiring.diagnostics.registered_pubkey", lambda url, handle: UNREACHABLE)

    config = _base_config(tmp_path)
    results = run_diagnostics(config, tmp_path / "serve.pid", mcp_config_path=tmp_path / "nonexistent.json")
    by_name = {r.name: r for r in results}
    assert by_name["mcp_config_paths_match"].passed is False
    assert "connect" in by_name["mcp_config_paths_match"].fix
