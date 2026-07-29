# Local MCP server exposing `relay ask` / `relay grant` / `relay revoke`
# as MCP tools. Per idea.md §6 "Distribution" and PRD.md §3 (Core User
# Flows) — this is the client/server both parties run locally.
#
# This file is intentionally thin: tool handlers below only parse
# arguments and call into agent/wiring/flows.py, which holds all the
# actual wiring logic and is independently tested without any MCP
# transport (agent/tests/test_integration.py). See agent/ARCHITECTURE.md.
#
# Judgment call: the `mcp` package actually installed (2.0.0) exposes a
# low-level callback-based Server (on_list_tools/on_call_tool), not the
# decorator-based FastMCP API older docs/training data describe. Wired
# against the real installed SDK rather than an assumed older shape.

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

from mcp import types
from mcp.server.lowlevel import Server

from resolver.rate_limiter import RateLimiter

from wiring.flows import PendingResponseRegistry, ask, grant, revoke, run_poll_loop
from wiring.local_state import LocalIdentity
from wiring.registry_client import RegistryClient, RegistryRejection

HANDLE = os.environ.get("RELAY_HANDLE", "")
KEY_DIR = os.environ.get("RELAY_KEY_DIR", os.path.expanduser("~/.relay/keys"))
CAPSULE_DIR = os.environ.get("RELAY_CAPSULE_DIR", os.path.expanduser("~/.relay/capsules"))
REGISTRY_URL = os.environ.get("RELAY_REGISTRY_URL", "http://localhost:8000")
POLL_INTERVAL_SECS = float(os.environ.get("RELAY_POLL_INTERVAL_SECS", "5"))

local_identity: LocalIdentity | None = None
registry: RegistryClient | None = None
rate_limiter = RateLimiter()
response_registry = PendingResponseRegistry()


def _ensure_initialized() -> tuple[LocalIdentity, RegistryClient]:
    global local_identity, registry
    if local_identity is None:
        if not HANDLE:
            raise RuntimeError("RELAY_HANDLE must be set before the server can sign anything")
        local_identity = LocalIdentity.load_or_create(HANDLE, KEY_DIR)
        registry = RegistryClient.create(REGISTRY_URL)
    return local_identity, registry


def start_background_poll_loop() -> threading.Thread:
    """Responsibility #5: a simple interval poll against registry's
    relay endpoint, run once per process — the only place that
    discovers inbound `ask` requests and delivers `ask_response`
    answers back to a waiting `ask()` call. Daemon thread: does not
    block process exit."""
    identity, client = _ensure_initialized()
    thread = threading.Thread(
        target=run_poll_loop,
        args=(identity, client, CAPSULE_DIR, rate_limiter, response_registry),
        kwargs={"interval_secs": POLL_INTERVAL_SECS},
        daemon=True,
    )
    thread.start()
    return thread


async def _on_list_tools(ctx, params) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[
        types.Tool(
            name="relay_ask",
            description="Ask a specific person's Relay agent a question; only pre-approved or live-approved capsule content is ever returned.",
            input_schema={
                "type": "object",
                "properties": {
                    "recipient": {"type": "string"},
                    "question": {"type": "string"},
                },
                "required": ["recipient", "question"],
            },
        ),
        types.Tool(
            name="relay_grant",
            description="Create a standing grant so a sender never has to be re-approved for a topic/capsule set.",
            input_schema={
                "type": "object",
                "properties": {
                    "grantee": {"type": "string"},
                    "grant_type": {"type": "string", "enum": ["standing", "ad_hoc"]},
                    "scope_capsule_ids": {"type": "array", "items": {"type": "string"}},
                    "expires_at": {"type": "string"},
                },
                "required": ["grantee", "grant_type", "scope_capsule_ids"],
            },
        ),
        types.Tool(
            name="relay_revoke",
            description="Revoke a standing grant immediately.",
            input_schema={
                "type": "object",
                "properties": {"grant_id": {"type": "string"}},
                "required": ["grant_id"],
            },
        ),
    ])


def dispatch_tool_call(name: str, arguments: dict) -> dict:
    """The actual tool dispatch logic, separated from the MCP-protocol
    result wrapping below so it's directly testable without any MCP
    types/transport involved."""
    identity, client = _ensure_initialized()
    try:
        if name == "relay_ask":
            return ask(identity, client, arguments["recipient"], arguments["question"], response_registry)
        if name == "relay_grant":
            expires_at = None
            if arguments.get("expires_at"):
                expires_at = datetime.fromisoformat(arguments["expires_at"])
            grant_id = grant(
                identity,
                client,
                arguments["grantee"],
                arguments["grant_type"],
                arguments["scope_capsule_ids"],
                expires_at=expires_at,
            )
            return {"id": grant_id}
        if name == "relay_revoke":
            revoke(identity, client, arguments["grant_id"])
            return {"revoked": True}
        raise ValueError(f"unknown tool {name!r}")
    except RegistryRejection as rejection:
        return {"error": rejection.outcome, "message": rejection.message}


async def _on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
    result = dispatch_tool_call(params.name, params.arguments or {})
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result))])


server = Server("relay", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)
