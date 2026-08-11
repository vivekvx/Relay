# Real MCP protocol test: two independent mcp_server.py module instances
# (one per identity — vivek the asker, rohan the approver), each driven
# by a genuine mcp.client.session.ClientSession doing a real
# initialize/list_tools/call_tool handshake over mcp.shared.memory's
# in-memory bidirectional transport against that module's own real
# mcp.server.lowlevel.Server — not a unit-level dispatch_tool_call()
# call, the actual MCP protocol serialization/session machinery, same
# rigor as every previous MCP task this session.
#
# Two independent module instances (not two calls into the same
# imported module) because mcp_server.py's identity/store globals are
# configured once from env vars at import time — this is the only way
# to represent two different people's local Relay agents in one test
# process.
#
# Message delivery between the two is driven by one explicit
# wiring.flows.poll_once() call per hop, reusing each module's own
# already-configured globals (identity/registry/stores) rather than a
# real background thread — deterministic and leak-free (an earlier
# version used start_background_poll_loop()'s daemon thread, which kept
# polling the shared ephemeral-Postgres registry after its own test
# function returned and destabilized the next test). Every actual
# request/decision/response below still goes through a genuine MCP tool
# call — only the "wait for a poll tick" mechanic changed.

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

from wiring.flows import poll_once
from tests.test_integration import make_identity, write_capsule

AGENT_DIR = Path(__file__).resolve().parents[1]
MCP_SERVER_PATH = AGENT_DIR / "mcp_server.py"


def _load_mcp_server_module(module_name: str, env: dict) -> object:
    """Loads a fresh, independent copy of mcp_server.py under its own
    module name, with its own env-var-derived globals — see module
    docstring for why two copies are needed."""
    backup = dict(os.environ)
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location(module_name, MCP_SERVER_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    finally:
        os.environ.clear()
        os.environ.update(backup)
    return module


def _deliver(module) -> None:
    """One explicit poll tick for `module`'s own identity, using that
    module's own already-configured globals — see file docstring for
    why this replaces a background thread here."""
    identity, registry = module._ensure_initialized()
    poll_once(
        identity, registry, module.CAPSULE_DIR, module.rate_limiter, module.response_registry,
        module.thread_store, module.disclosure_log, pending_approval_store=module.pending_approval_store,
    )


async def _call_tool(module, name: str, arguments: dict) -> dict:
    """One real initialize + one real call_tool per invocation."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        server_read, server_write = server_streams
        client_read, client_write = client_streams
        server_task = asyncio.create_task(
            module.server.run(server_read, server_write, module.server.create_initialization_options())
        )
        try:
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
                return json.loads(result.content[0].text)
        finally:
            server_task.cancel()
            try:
                await server_task
            except (asyncio.CancelledError, Exception):
                pass


def _make_modules(tmp_path, registry_url: str, suffix: str) -> tuple[object, object]:
    vivek_module = _load_mcp_server_module(f"mcp_server_vivek_{suffix}", {
        "CALLSIGN_HANDLE": "vivek",
        "CALLSIGN_KEY_DIR": str(tmp_path / "vivek" / "keys"),
        "CALLSIGN_CAPSULE_DIR": str(tmp_path / "vivek_capsules"),
        "CALLSIGN_REGISTRY_URL": registry_url,
        "CALLSIGN_THREAD_STORE": str(tmp_path / f"vivek_threads_{suffix}.json"),
        "CALLSIGN_DISCLOSURE_LOG": str(tmp_path / f"vivek_disclosure_{suffix}.json"),
        "CALLSIGN_PENDING_APPROVALS": str(tmp_path / f"vivek_pending_{suffix}.json"),
        "CALLSIGN_CONTACTS": str(tmp_path / f"vivek_contacts_{suffix}.json"),
    })
    rohan_module = _load_mcp_server_module(f"mcp_server_rohan_{suffix}", {
        "CALLSIGN_HANDLE": "rohan",
        "CALLSIGN_KEY_DIR": str(tmp_path / "rohan" / "keys"),
        "CALLSIGN_CAPSULE_DIR": str(tmp_path / "rohan_capsules"),
        "CALLSIGN_REGISTRY_URL": registry_url,
        "CALLSIGN_THREAD_STORE": str(tmp_path / f"rohan_threads_{suffix}.json"),
        "CALLSIGN_DISCLOSURE_LOG": str(tmp_path / f"rohan_disclosure_{suffix}.json"),
        "CALLSIGN_PENDING_APPROVALS": str(tmp_path / f"rohan_pending_{suffix}.json"),
        "CALLSIGN_CONTACTS": str(tmp_path / f"rohan_contacts_{suffix}.json"),
    })
    return vivek_module, rohan_module


def test_both_directions_approval_loop_via_real_mcp_calls(tmp_path, registry_client, monkeypatch):
    # Real notifications aren't exercised here (already covered for real
    # in the prior relay-serve task's manual walkthrough); avoid a real
    # GUI popup firing every automated test run.
    monkeypatch.setattr("wiring.flows.notify_new_approval_request", lambda sender, query: True)

    make_identity("vivek", tmp_path, registry_client)
    make_identity("rohan", tmp_path, registry_client)

    write_capsule(
        tmp_path / "rohan_capsules", "backoff", "vivek", "webhook,retry",
        "Use exponential backoff with jitter for webhook retries.",
    )

    vivek_module, rohan_module = _make_modules(tmp_path, registry_client.base_url, "loop")

    async def run():
        # Asker side, entirely via MCP: callsign_call.
        ask_result = await _call_tool(vivek_module, "callsign_call", {
            "recipient": "rohan",
            "question": "how do you handle webhook retries?",
            "reason": "debugging a similar retry issue in my own project",
            "urgency": "not time-sensitive",
        })
        assert ask_result["status"] == "pending"  # rohan hasn't polled yet
        request_id = ask_result["nonce"]

        _deliver(rohan_module)  # rohan's poll tick: verifies+decrypts+queues headless

        # Approver side, entirely via MCP: callsign_missed.
        pending_result = await _call_tool(rohan_module, "callsign_missed", {})
        assert len(pending_result["pending"]) == 1
        item = pending_result["pending"][0]
        assert item["request_id"] == request_id
        assert item["sender"] == "vivek"
        assert item["question"] == "how do you handle webhook retries?"
        assert item["reason"] == "debugging a similar retry issue in my own project"
        assert item["urgency"] == "not time-sensitive"
        assert item["candidates"][0]["capsule_id"] == "backoff"

        # Approver side, entirely via MCP: callsign_answer.
        respond_result = await _call_tool(rohan_module, "callsign_answer", {
            "request_id": request_id,
            "decision": "approve_whole",
            "capsule_ids": ["backoff"],
        })
        assert respond_result["outcome"] == "approved_whole"
        assert respond_result["cited_capsule_ids"] == ["backoff"]

        _deliver(vivek_module)  # vivek's poll tick: delivers the ask_response

        # Asker side, entirely via MCP: callsign_callback gets the real answer.
        check_result = await _call_tool(vivek_module, "callsign_callback", {"request_id": request_id})
        assert check_result["status"] == "answered"
        assert check_result["outcome"] == "approved_whole"
        assert check_result["cited_capsule_ids"] == ["backoff"]
        assert "exponential backoff" in check_result["answer"]

    asyncio.run(run())
    del sys.modules[vivek_module.__name__]
    del sys.modules[rohan_module.__name__]


def test_ambiguous_decision_is_rejected_not_guessed(tmp_path, registry_client, monkeypatch):
    monkeypatch.setattr("wiring.flows.notify_new_approval_request", lambda sender, query: True)

    make_identity("vivek", tmp_path, registry_client)
    make_identity("rohan", tmp_path, registry_client)
    write_capsule(tmp_path / "rohan_capsules", "backoff", "vivek", "webhook,retry", "Use exponential backoff with jitter.")

    vivek_module, rohan_module = _make_modules(tmp_path, registry_client.base_url, "ambig")

    async def run():
        ask_result = await _call_tool(vivek_module, "callsign_call", {"recipient": "rohan", "question": "webhook retries?"})
        request_id = ask_result["nonce"]

        _deliver(rohan_module)

        pending_result = await _call_tool(rohan_module, "callsign_missed", {})
        assert len(pending_result["pending"]) == 1

        # No capsule_ids given for approve_whole — ambiguous, must be
        # rejected, never guessed/defaulted to approval.
        respond_result = await _call_tool(rohan_module, "callsign_answer", {
            "request_id": request_id, "decision": "approve_whole",
        })
        assert respond_result["error"] == "ambiguous_decision"

        # The request is still queued — rejecting the ambiguous call did
        # not silently consume or answer it.
        still_pending = await _call_tool(rohan_module, "callsign_missed", {})
        assert len(still_pending["pending"]) == 1

    asyncio.run(run())
    del sys.modules[vivek_module.__name__]
    del sys.modules[rohan_module.__name__]
