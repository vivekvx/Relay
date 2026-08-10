# relay_setup / ensure_listener_running idempotency — the "call it twice
# in a row, second call is a safe no-op" tests this whole task is built
# around.

from unittest.mock import MagicMock, patch

from wiring.setup import ensure_listener_running, ensure_setup


def test_ensure_setup_twice_is_idempotent_no_corruption(tmp_path, registry_client):
    config_path = tmp_path / "config.toml"
    key_dir = str(tmp_path / "keys" / "vivek")
    capsule_dir = str(tmp_path / "capsules")
    registry_url = registry_client.base_url

    first = ensure_setup("vivek", capsule_dir, registry_url, key_dir, config_path)
    assert first.already_configured is False
    assert first.already_registered is False
    assert first.relay_number is not None
    assert config_path.exists()

    first_identity = registry_client.get_identity("vivek")

    second = ensure_setup("vivek", capsule_dir, registry_url, key_dir, config_path)
    assert second.already_configured is True
    assert second.already_registered is True
    assert second.relay_number == first.relay_number

    second_identity = registry_client.get_identity("vivek")
    assert second_identity["public_key_hex"] == first_identity["public_key_hex"]


def test_ensure_listener_running_twice_spawns_only_once(tmp_path):
    pid_file = tmp_path / "serve.pid"
    meta_file = tmp_path / "serve.json"
    log_file = tmp_path / "serve.log"

    fake_process = MagicMock()
    fake_process.pid = 12345
    popen_fn = MagicMock(return_value=fake_process)

    with patch("wiring.setup.pid_alive_from_file", side_effect=[None, 12345, 12345]), \
         patch("wiring.setup.time.sleep"):
        first = ensure_listener_running(tmp_path, pid_file, meta_file, log_file, tmp_path, popen_fn=popen_fn)
        assert first["status"] == "started"
        assert popen_fn.call_count == 1

        second = ensure_listener_running(tmp_path, pid_file, meta_file, log_file, tmp_path, popen_fn=popen_fn)
        assert second["status"] == "already_running"
        assert popen_fn.call_count == 1  # not called again
