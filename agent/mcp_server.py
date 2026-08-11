# Local MCP server exposing `callsign call` / `callsign allow` /
# `callsign block` as MCP tools. Per idea.md §6 "Distribution" and
# PRD.md §3 (Core User Flows) — this is the client/server both parties
# run locally.
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
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp import types
from mcp.server.lowlevel import Server

from resolver.rate_limiter import RateLimiter

from wiring.contacts import ContactsStore, resolve_recipient
from wiring.diagnostics import run_diagnostics
from wiring.disclosure_log import DisclosureLog
from wiring.error_messages import translate_error
from wiring.flows import (
    PendingResponseRegistry,
    ask,
    check_pending,
    grant,
    list_pending_approvals_with_candidates,
    resolve_pending_approval,
    revoke,
    run_poll_loop,
)
from wiring.local_state import LocalIdentity, load_capsules
from wiring.paths import REGISTRY_HOME, SERVE_META_FILE, SERVE_PID_FILE, migrate_from_relay_if_needed
from wiring.pending_approvals import PendingApproval, PendingApprovalStore
from wiring.registry_client import RegistryClient, RegistryRejection
from wiring.setup import ensure_listener_running, ensure_setup
from wiring.threads import ThreadStore
from wiring.trace import generate_trace_id

logger = logging.getLogger("callsign.agent")

from approval import ApprovalDecision, ExcerptBounds, Outcome

migrate_from_relay_if_needed()

HANDLE = os.environ.get("CALLSIGN_HANDLE", "")
KEY_DIR = os.environ.get("CALLSIGN_KEY_DIR", os.path.expanduser("~/.callsign/keys"))
CAPSULE_DIR = os.environ.get("CALLSIGN_CAPSULE_DIR", os.path.expanduser("~/.callsign/capsules"))
REGISTRY_URL = os.environ.get("CALLSIGN_REGISTRY_URL", "http://localhost:8000")
POLL_INTERVAL_SECS = float(os.environ.get("CALLSIGN_POLL_INTERVAL_SECS", "5"))
THREAD_STORE_PATH = os.environ.get("CALLSIGN_THREAD_STORE", os.path.expanduser("~/.callsign/threads.json"))
DISCLOSURE_LOG_PATH = os.environ.get("CALLSIGN_DISCLOSURE_LOG", os.path.expanduser("~/.callsign/disclosure_log.json"))
PENDING_APPROVALS_PATH = os.environ.get(
    "CALLSIGN_PENDING_APPROVALS", os.path.expanduser("~/.callsign/pending_approvals.json")
)
CONFIG_PATH = Path(os.environ.get("CALLSIGN_CONFIG", str(Path.home() / ".callsign" / "config.toml")))
CONTACTS_PATH = os.environ.get("CALLSIGN_CONTACTS", os.path.expanduser("~/.callsign/contacts.json"))

local_identity: LocalIdentity | None = None
registry: RegistryClient | None = None
rate_limiter = RateLimiter()
response_registry = PendingResponseRegistry()
thread_store = ThreadStore(THREAD_STORE_PATH)
disclosure_log = DisclosureLog(DISCLOSURE_LOG_PATH)
pending_approval_store = PendingApprovalStore(PENDING_APPROVALS_PATH)
contacts_store = ContactsStore(CONTACTS_PATH)


def _ensure_initialized() -> tuple[LocalIdentity, RegistryClient]:
    global local_identity, registry
    if local_identity is None:
        if not HANDLE:
            raise RuntimeError("CALLSIGN_HANDLE must be set before the server can sign anything")
        local_identity = LocalIdentity.load_or_create(HANDLE, KEY_DIR)
        registry = RegistryClient.create(REGISTRY_URL)
    return local_identity, registry


def start_background_poll_loop() -> threading.Thread:
    """Responsibility #5: a simple interval poll against registry's
    relay endpoint, run once per process — the only place that
    discovers inbound `ask` requests and delivers `ask_response`
    answers back to a waiting `ask()` call. Daemon thread: does not
    block process exit.

    pending_approval_store is ALWAYS passed here (headless mode) — this
    process's stdin is the JSON-RPC channel Claude Code talks to it
    over, not an interactive terminal, so process_incoming_ask must
    never call input() on it. An ad hoc approval request queues instead
    (same wiring/pending_approvals.py store `callsign standby` uses) and
    fires the same native notification; callsign_missed/
    callsign_answer below are this process's own equivalent of
    `callsign missed`, callable from inside Paul's own chat."""
    identity, client = _ensure_initialized()
    thread = threading.Thread(
        target=run_poll_loop,
        args=(identity, client, CAPSULE_DIR, rate_limiter, response_registry, thread_store, disclosure_log),
        kwargs={"interval_secs": POLL_INTERVAL_SECS, "pending_approval_store": pending_approval_store},
        daemon=True,
    )
    thread.start()
    return thread


async def _on_list_tools(ctx, params) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[
        types.Tool(
            name="callsign_call",
            description="Ask a specific person's Callsign agent a question; only pre-approved or live-approved capsule content is ever returned.",
            input_schema={
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "a saved contact name, or a raw handle directly",
                    },
                    "question": {"type": "string"},
                    "thread_id": {
                        "type": "string",
                        "description": "continue an existing conversation (from a prior callsign_call response's thread_id); omit to start a new one",
                    },
                    "reason": {
                        "type": "string",
                        "description": "why you need this (one line); shown to the approver as a distinct field, defaults to 'no reason given' if omitted",
                    },
                    "urgency": {
                        "type": "string",
                        "description": "whether this is time-sensitive, and why; defaults to 'not time-sensitive' if omitted",
                    },
                },
                "required": ["recipient", "question"],
            },
        ),
        types.Tool(
            name="callsign_allow",
            description="Create a standing grant so a sender never has to be re-approved for a topic/capsule set.",
            input_schema={
                "type": "object",
                "properties": {
                    "grantee": {
                        "type": "string",
                        "description": "a saved contact name, or a raw handle directly",
                    },
                    "grant_type": {"type": "string", "enum": ["standing", "ad_hoc"]},
                    "scope_capsule_ids": {"type": "array", "items": {"type": "string"}},
                    "expires_at": {"type": "string"},
                },
                "required": ["grantee", "grant_type", "scope_capsule_ids"],
            },
        ),
        types.Tool(
            name="callsign_block",
            description="Revoke a standing grant immediately.",
            input_schema={
                "type": "object",
                "properties": {"grant_id": {"type": "string"}},
                "required": ["grant_id"],
            },
        ),
        types.Tool(
            name="callsign_callback",
            description="Check whether a pending callsign_call (request_id from its 'pending' response) has been answered yet.",
            input_schema={
                "type": "object",
                "properties": {"request_id": {"type": "string"}},
                "required": ["request_id"],
            },
        ),
        types.Tool(
            name="callsign_setup",
            description=(
                "Set up Callsign end-to-end: writes local config, registers this identity with the registry, "
                "and starts the background listener so incoming asks are reachable even when this chat isn't "
                "open. Safe to call repeatedly — if already set up, reports current status without re-creating "
                "or corrupting anything."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "handle": {"type": "string"},
                    "capsule_dir": {"type": "string"},
                    "registry_url": {"type": "string"},
                    "key_dir": {"type": "string"},
                    "force": {"type": "boolean", "description": "proceed even if already registered with a different key"},
                },
                "required": ["handle"],
            },
        ),
        types.Tool(
            name="callsign_signal",
            description=(
                "Run diagnostic checks: registry reachable, identity registered, local key matches registered, "
                "listener running, MCP config paths correct. Each check reports pass/fail with a specific fix."
            ),
            input_schema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="callsign_missed",
            description=(
                "List ad hoc approval requests waiting for YOU to decide, as the approver — the same queue "
                "`callsign standby`/`callsign missed` use, just returned as structured data so this chat can present "
                "it conversationally. Call this when the person asks to check their Callsign requests, or after "
                "a Callsign notification."
            ),
            input_schema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="callsign_answer",
            description=(
                "Answer one queued approval request (from callsign_missed) with an unambiguous decision. "
                "If the person's chat message doesn't clearly map to exactly one decision type and its required "
                "fields, ask a clarifying question instead of guessing — this tool does not infer intent."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "from callsign_missed's request_id field"},
                    "decision": {
                        "type": "string",
                        "enum": ["approve_whole", "approve_excerpt", "deny", "manual_answer"],
                    },
                    "capsule_ids": {
                        "type": "array", "items": {"type": "string"},
                        "description": "required for approve_whole: which of the request's candidate documents to share in full",
                    },
                    "excerpt": {
                        "type": "object",
                        "description": "required for approve_excerpt",
                        "properties": {
                            "capsule_id": {"type": "string"},
                            "start": {"type": "integer"},
                            "end": {"type": "integer"},
                        },
                    },
                    "manual_answer": {"type": "string", "description": "required for manual_answer"},
                },
                "required": ["request_id", "decision"],
            },
        ),
    ])


def _build_decision_from_response_args(pending: PendingApproval, arguments: dict, capsules_by_id: dict) -> ApprovalDecision:
    """Translates callsign_answer's structured MCP args into the
    real ApprovalDecision type — SAME type, same __post_init__ invariants
    approval/interaction.py's terminal picker already relies on (this
    task's explicit "do not reimplement approval decision handling").
    This function only replaces *how the human's choice arrived*
    (structured args instead of a terminal picker's parsed free text),
    never what a decision means or what it's allowed to do.

    Raises ValueError for anything ambiguous, missing, or invalid — the
    caller must surface this back to Claude Code as an error so it asks
    a clarifying question and calls the tool again unambiguously, never
    guesses or silently defaults to approval (this task's explicit DO
    NOT BUILD)."""
    decision_type = arguments.get("decision")
    candidate_ids = set(pending.candidate_capsule_ids)

    if decision_type == "approve_whole":
        capsule_ids = arguments.get("capsule_ids") or []
        if not capsule_ids:
            raise ValueError("approve_whole requires a non-empty capsule_ids list")
        unknown = [cid for cid in capsule_ids if cid not in candidate_ids]
        if unknown:
            raise ValueError(f"not candidate documents on this request: {unknown}")
        return ApprovalDecision(outcome=Outcome.APPROVED_WHOLE, approved_capsule_ids=tuple(capsule_ids))

    if decision_type == "approve_excerpt":
        excerpt = arguments.get("excerpt") or {}
        capsule_id, start, end = excerpt.get("capsule_id"), excerpt.get("start"), excerpt.get("end")
        if capsule_id not in candidate_ids:
            raise ValueError(f"{capsule_id!r} is not a candidate document on this request")
        content_len = len(capsules_by_id[capsule_id].content) if capsule_id in capsules_by_id else 0
        if not isinstance(start, int) or not isinstance(end, int) or not (0 <= start < end <= content_len):
            raise ValueError(f"excerpt bounds must satisfy 0 <= start < end <= {content_len}")
        return ApprovalDecision(
            outcome=Outcome.APPROVED_EXCERPT, excerpt=ExcerptBounds(capsule_id=capsule_id, start=start, end=end),
        )

    if decision_type == "deny":
        return ApprovalDecision(outcome=Outcome.DENIED)

    if decision_type == "manual_answer":
        manual_answer = (arguments.get("manual_answer") or "").strip()
        if not manual_answer:
            raise ValueError("manual_answer requires non-empty text")
        return ApprovalDecision(outcome=Outcome.MANUAL_ANSWER, manual_answer=manual_answer)

    raise ValueError(
        f"unrecognized or missing decision {decision_type!r} — must be exactly one of "
        f"approve_whole, approve_excerpt, deny, manual_answer"
    )


def dispatch_tool_call(name: str, arguments: dict) -> dict:
    """The actual tool dispatch logic, separated from the MCP-protocol
    result wrapping below so it's directly testable without any MCP
    types/transport involved."""
    identity, client = _ensure_initialized()
    trace_id = generate_trace_id()
    logger.info("mcp_tool_call trace_id=%s tool=%s", trace_id, name)
    try:
        if name == "callsign_call":
            recipient = resolve_recipient(contacts_store, client, arguments["recipient"])
            result = ask(
                identity, client, recipient, arguments["question"], response_registry, thread_store,
                thread_id=arguments.get("thread_id"),
                reason=arguments.get("reason", ""), urgency=arguments.get("urgency", ""),
            )
            return {**result, "trace_id": result.get("trace_id", trace_id)}
        if name == "callsign_allow":
            expires_at = None
            if arguments.get("expires_at"):
                expires_at = datetime.fromisoformat(arguments["expires_at"])
            grantee = resolve_recipient(contacts_store, client, arguments["grantee"])
            grant_id = grant(
                identity,
                client,
                grantee,
                arguments["grant_type"],
                arguments["scope_capsule_ids"],
                expires_at=expires_at,
                trace_id=trace_id,
            )
            return {"id": grant_id, "trace_id": trace_id}
        if name == "callsign_block":
            revoke(identity, client, arguments["grant_id"], trace_id=trace_id)
            return {"revoked": True, "trace_id": trace_id}
        if name == "callsign_callback":
            result = check_pending(
                identity, client, CAPSULE_DIR, rate_limiter, response_registry, thread_store, disclosure_log,
                arguments["request_id"],
            )
            return {**result, "trace_id": trace_id}
        if name == "callsign_setup":
            setup_handle = arguments.get("handle") or HANDLE
            setup_result = ensure_setup(
                setup_handle,
                arguments.get("capsule_dir") or CAPSULE_DIR,
                arguments.get("registry_url") or REGISTRY_URL,
                arguments.get("key_dir") or KEY_DIR,
                CONFIG_PATH,
                force=arguments.get("force", False),
            )
            listener_result = ensure_listener_running(
                REGISTRY_HOME, SERVE_PID_FILE, SERVE_META_FILE, REGISTRY_HOME / "serve.log", Path(__file__).resolve().parent
            )
            return {
                "already_configured": setup_result.already_configured,
                "already_registered": setup_result.already_registered,
                "relay_number": setup_result.relay_number,
                "warnings": setup_result.warnings,
                "listener": listener_result,
                "trace_id": trace_id,
            }
        if name == "callsign_signal":
            config = {"registry_url": REGISTRY_URL, "handle": HANDLE, "key_dir": KEY_DIR}
            mcp_config_path = Path(os.environ.get("CALLSIGN_MCP_CONFIG_PATH", "")) if os.environ.get("CALLSIGN_MCP_CONFIG_PATH") else None
            results = run_diagnostics(config, SERVE_PID_FILE, mcp_config_path=mcp_config_path)
            return {
                "checks": [
                    {"name": r.name, "passed": r.passed, "detail": r.detail, "fix": r.fix} for r in results
                ],
                "trace_id": trace_id,
            }
        if name == "callsign_missed":
            return {
                "pending": list_pending_approvals_with_candidates(CAPSULE_DIR, pending_approval_store),
                "trace_id": trace_id,
            }
        if name == "callsign_answer":
            request_id = arguments["request_id"]
            pending = pending_approval_store.get(request_id)
            if pending is None:
                return {
                    "error": "not_found",
                    "message": f"no pending request {request_id!r} — it may have already been answered or expired",
                    "fix": translate_error("not_found"),
                    "trace_id": trace_id,
                }
            capsules_by_id = load_capsules(CAPSULE_DIR)
            try:
                decision = _build_decision_from_response_args(pending, arguments, capsules_by_id)
            except ValueError as e:
                return {"error": "ambiguous_decision", "message": str(e), "trace_id": trace_id}
            response = resolve_pending_approval(
                identity, client, CAPSULE_DIR, thread_store, disclosure_log, pending,
                decision=decision, input_fn=lambda _: "n", output_fn=lambda _: None,
            )
            pending_approval_store.pop(request_id)
            return {**response, "trace_id": trace_id}
        raise ValueError(f"unknown tool {name!r}")
    except RegistryRejection as rejection:
        return {
            "error": rejection.outcome,
            "message": rejection.message,
            "fix": translate_error(rejection.outcome, rejection.message),
            "trace_id": trace_id,
        }
    except httpx.HTTPError as exc:
        return {
            "error": "registry_unreachable",
            "message": str(exc),
            "fix": translate_error("registry_unreachable"),
            "trace_id": trace_id,
        }
    except ValueError as e:
        return {"error": "invalid_request", "message": str(e), "trace_id": trace_id}


async def _on_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
    result = dispatch_tool_call(params.name, params.arguments or {})
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result))])


server = Server("callsign", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)


# No run loop previously existed here — `server` was defined but nothing
# ever called .run(), so this file could not actually be launched as an
# MCP server process. This is the missing piece: stdio transport (the
# only transport Claude Code's local MCP registration needs), plus
# kicking off the background poll loop so callsign_call has something
# delivering ask_response items back to it.
async def _amain() -> None:
    import mcp.server.stdio

    start_background_poll_loop()
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    import asyncio
    import sys

    # stderr, not stdout — stdout is the MCP JSON-RPC transport
    # (mcp.server.stdio.stdio_server below); writing logs there would
    # corrupt the protocol stream.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="event=%(message)s logger=%(name)s")
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
