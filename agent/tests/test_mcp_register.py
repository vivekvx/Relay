import json

from cli import _mcp_server_entry, _write_mcp_entry


def _config(tmp_path):
    return {
        "handle": "vivek",
        "key_dir": str(tmp_path / "keys"),
        "capsule_dir": str(tmp_path / "capsules"),
        "registry_url": "https://relay-registry.onrender.com",
    }


def test_mcp_register_twice_is_idempotent(tmp_path):
    mcp_config_path = tmp_path / ".mcp.json"
    entry = _mcp_server_entry(_config(tmp_path))

    _write_mcp_entry(mcp_config_path, entry)
    first_content = mcp_config_path.read_text()

    _write_mcp_entry(mcp_config_path, entry)
    second_content = mcp_config_path.read_text()

    data = json.loads(second_content)
    assert list(data["mcpServers"].keys()) == ["callsign"]
    assert first_content == second_content


def test_mcp_register_repairs_stale_entry(tmp_path):
    mcp_config_path = tmp_path / ".mcp.json"
    stale_entry = {"command": "/wrong/path", "args": [], "cwd": "/wrong", "env": {}}
    mcp_config_path.write_text(json.dumps({"mcpServers": {"callsign": stale_entry}}))

    correct_entry = _mcp_server_entry(_config(tmp_path))
    _write_mcp_entry(mcp_config_path, correct_entry)

    data = json.loads(mcp_config_path.read_text())
    assert data["mcpServers"]["callsign"] == correct_entry
    assert list(data["mcpServers"].keys()) == ["callsign"]


def test_mcp_register_preserves_other_existing_servers(tmp_path):
    mcp_config_path = tmp_path / ".mcp.json"
    mcp_config_path.write_text(json.dumps({"mcpServers": {"other-tool": {"command": "foo"}}}))

    entry = _mcp_server_entry(_config(tmp_path))
    _write_mcp_entry(mcp_config_path, entry)

    data = json.loads(mcp_config_path.read_text())
    assert set(data["mcpServers"].keys()) == {"other-tool", "callsign"}
