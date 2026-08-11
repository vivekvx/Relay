from wiring.local_state import LocalIdentity
from wiring.threads import ThreadStore

import mcp_server
from wiring.flows import PendingResponseRegistry, ask
from wiring.registry_client import RegistryRejection
from wiring.trace import generate_trace_id


def _make_identity(handle: str, tmp_path, registry_client) -> LocalIdentity:
    identity = LocalIdentity.load_or_create(handle, str(tmp_path / handle / "keys"))
    registry_client.register_identity(handle, identity.public_key_hex, identity.encryption_public_key_hex)
    return identity


def test_generate_trace_id_produces_distinct_values():
    a, b = generate_trace_id(), generate_trace_id()
    assert a != b
    assert len(a) == 16  # TRACE_ID_HEX_LEN


def test_ask_pending_result_includes_trace_id(tmp_path, registry_client):
    vivek = _make_identity("vivek", tmp_path, registry_client)
    _make_identity("rohan", tmp_path, registry_client)

    result = ask(
        vivek, registry_client, "rohan", "does this include a trace_id?",
        PendingResponseRegistry(), ThreadStore(str(tmp_path / "threads.json")),
        wait_attempts=1, wait_interval=0,
    )
    assert result["status"] == "pending"
    assert result["trace_id"]


def test_two_ask_calls_get_different_trace_ids(tmp_path, registry_client):
    vivek = _make_identity("vivek", tmp_path, registry_client)
    _make_identity("rohan", tmp_path, registry_client)

    response_registry = PendingResponseRegistry()
    thread_store = ThreadStore(str(tmp_path / "threads.json"))

    first = ask(vivek, registry_client, "rohan", "q1", response_registry, thread_store, wait_attempts=1, wait_interval=0)
    second = ask(vivek, registry_client, "rohan", "q2", response_registry, thread_store, wait_attempts=1, wait_interval=0)
    assert first["trace_id"] != second["trace_id"]


def test_dispatch_tool_call_error_dict_includes_trace_id(monkeypatch):
    monkeypatch.setattr(mcp_server, "_ensure_initialized", lambda: (None, None))

    def _boom(*a, **k):
        raise RegistryRejection(404, "unknown_recipient", "nope")

    monkeypatch.setattr(mcp_server, "resolve_recipient", _boom)
    result = mcp_server.dispatch_tool_call("callsign_call", {"recipient": "nobody", "question": "hi"})
    assert result["error"] == "unknown_recipient"
    assert result["trace_id"]
    assert "fix" in result
