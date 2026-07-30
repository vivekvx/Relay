# agent/ — architecture (MCP server + wiring)

`agent/mcp_server.py` exposes three MCP tools (`relay_ask`, `relay_grant`,
`relay_revoke`). All real logic lives in `agent/wiring/`, independently
testable without any MCP transport (`agent/tests/test_integration.py`).

## Files

- `wiring/registry_client.py` — HTTP client over the registry's existing
  API. No business logic, just request/response shaping.
- `wiring/nonce.py` — cryptographically random nonce generation
  (32 hex chars, identity's contract).
- `wiring/local_state.py` — this machine's own keys (via the real
  `relay_identity` PyO3 bridge, `identity/python/`), a minimal capsule
  loader (stand-in, see below), and the grant canonical-payload encoder
  (duplicated from `registry/services/grant_payload.py` — see below).
- `wiring/flows.py` — the three tools' actual wiring: `ask`/
  `process_incoming_ask`/`process_incoming_ask_response`, `grant`/
  `revoke`, `poll_once`/`run_poll_loop`.
- `mcp_server.py` — thin MCP protocol layer; `dispatch_tool_call` is the
  only function it adds beyond wiring calls, and it's plain Python,
  testable without MCP types.

## Pipeline: standing-grant `relay ask`

1. **Caller** (`flows.ask`) — signs a `RequestPayload` via
   `relay_identity.sign_payload`, encrypts the question via
   `relay_identity.encrypt` (recipient's X25519 key, fetched from
   registry), submits via `RegistryClient.submit_relay`.
2. **Registry** (`relay_service.submit_relay_request`, unchanged) —
   verifies signature/nonce/timestamp, enqueues.
3. **Recipient's poll loop** (`flows.poll_once` → `process_incoming_ask`)
   — `RegistryClient.fetch_pending`, then **re-verifies** the signature
   locally (`relay_identity.verify_payload`) and decrypts
   (`relay_identity.decrypt`) — defense in depth, not trusting the
   registry's accept-time check alone (PRD.md §3.2 step 4).
4. **Recipient's local resolver** — `_my_grants_as_grantor` fetches
   `RegistryClient.list_grants`, filters to grants THIS identity itself
   created (see judgment calls), then `resolver.resolve_scope`.
5. Permitted set non-empty → **standing-grant branch**: response built
   directly from those capsules' full content, no approval prompt (PRD.md
   §3.1 step 5 — the grant already is consent).
6. **Recipient** signs+encrypts the response (`request_type="ask_response"`),
   submits back via registry.
7. **Caller's poll loop** (`process_incoming_ask_response`) verifies,
   decrypts, and hands the answer to `ask()`'s waiting caller via
   `PendingResponseRegistry`.

## Pipeline: ad hoc `relay ask`

Steps 1–4 identical. Step 5 diverges:

5. Permitted set empty → **ad hoc branch**:
   a. `resolver.search_candidates` (deterministic, no LLM) finds
      candidate capsule IDs.
   b. `resolver.types.ApprovalRequest` constructed locally
      (`created_at`, `expiry_duration` default 5h, `candidate_capsule_ids`).
   c. `approval.request_approval` — a **blocking** terminal prompt.
      Outcome maps directly to the response: `APPROVED_WHOLE`/
      `APPROVED_EXCERPT` → capsule content; `MANUAL_ANSWER` → the typed
      text only, **no capsule content** (approval/'s own invariant,
      preserved — proven by
      `test_ad_hoc_ask_manual_answer_no_capsule_content`); `DENIED`/
      `EXPIRED` → denial, no content
      (`test_ad_hoc_ask_deny_no_capsule_content_anywhere`).
   d. `approval.request_grant_promotion` — a **separate** call, only
      after a decision. If accepted, `flows.grant` is called
      **separately** from the response relay (never conflated into one
      registry call — this task's explicit requirement).
6–7. Same as standing-grant.

Rate limiting: `resolver.rate_limiter.RateLimiter.check_and_record` runs
before scope resolution, for both branches — an over-limit sender gets a
denial response with no resolver/approval involvement at all.

## Pipeline: `relay grant` / `relay revoke`

1. `flows.grant`/`flows.revoke` build a canonical byte encoding of the
   grant fields (`local_state.encode_grant_create_payload`/
   `encode_grant_revoke_payload`) and sign it via
   `relay_identity.sign_bytes` — **not** `sign_payload`, since grant
   fields (`scope_capsule_ids`, `expires_at`) don't fit `RequestPayload`'s
   fixed 5 fields. `sign_bytes`/`verify_bytes` were added to `identity/`
   and its PyO3 bridge as part of this task (see "New identity/ primitive"
   below).
2. `RegistryClient.create_grant`/`revoke_grant` → `registry/api/
   grant_routes.py` → `grant_service.create_grant_signed`/
   `revoke_grant_signed` (also added as part of this task — see "Registry
   fixes" below) — verifies the signature before any state mutation.
3. Revocation takes effect immediately at the registry (`revoked_at`
   set); local enforcement (checked at capsule-load time, not request
   time) is `resolver.resolve_scope`'s existing job, unchanged.

## New identity/ primitive: `sign_bytes` / `verify_bytes`

`identity/`'s only signing function was `sign_payload(key,
RequestPayload)` — bound to the fixed ask/relay format. Grant/revoke need
to sign a different field shape. Added `sign_bytes`/`verify_bytes` to
`identity/src/signing.rs`/`verification.rs` (generic, no timestamp/nonce
assumptions — the caller's own byte format owns any freshness/replay
checks it needs) and bridged them through `identity/python/`. Proven by
3 new Rust tests + 4 new Python bridge tests, all passing alongside the
existing suites.

## Registry fixes (prerequisite tasks, not this task's scope, but load-bearing)

Two registry-side gaps were found and fixed before this task could
proceed correctly:

1. `GET /relay/pending/{recipient}` 500'd on any real payload (raw
   `LargeBinary` never hex-encoded before JSON serialization). Fixed:
   `payload_hex` field + `response_model`.
2. `POST /grants`/`POST /grants/revoke` accepted `grantor`/`grant_id` as
   unauthenticated claims — direct contradiction of PRD.md §5 R2. Fixed:
   signature verification before any grant state mutation, mirroring
   `/relay`'s existing pattern.

## Known gaps this task inherits (documented, not solved here)

1. ~~`resolver.search_candidates` returns bare capsule IDs~~ — **closed.**
   `search_candidates` now returns `SearchCandidate` (capsule ID +
   `match_reason` + optional `relevant_span`) per result; `approval.
   request_approval` renders the "why matched" line and offers the
   suggested-span confirm shortcut when a `match_info` map is supplied
   (see `agent/approval/ARCHITECTURE.md`). `wiring/flows.py` still only
   needs bare capsule IDs for `ApprovalRequest.candidate_capsule_ids`, so
   it unwraps `SearchCandidate.capsule_id` there rather than threading
   `match_info` through to the terminal prompt — wiring `match_info`
   end-to-end into the live approval flow is future work, not done here.
2. **`agent/capsules/` doesn't exist** — still a docstring-only stub.
   `wiring/local_state.load_capsules` is a minimal, explicitly-flagged
   stand-in: direct `*.md` file read with a simple `key: value` header
   format invented for this task, not SQLite/FTS5. Replacing it with the
   real capsule store should only require swapping `load_capsules`'s
   implementation — `flows.py` only touches `Capsule.id`/`.shareable`/
   `.shareable_with`/`.tags`/`.content`, the same fields `resolver.types.
   Capsule` already defines.

## Judgment calls

1. **`_my_grants_as_grantor`'s client-side `grantor == self.handle`
   filter.** Registry's `GET /grants` only filters by `grantee`; a row's
   `grantor` field isn't independently authenticated at read time (only
   at write time, via `create_grant_signed`). Trusting every returned
   grant regardless of grantor would let anyone's grant records affect
   local scope resolution as long as capsule IDs happened to collide.
   This filter is a deliberate extra guard: only grants **this identity
   itself created** are ever passed to `resolve_scope`.
2. **Response envelope is a small JSON object** (`outcome`, `answer`,
   `cited_capsule_ids`, `in_reply_to_nonce`) inside the encrypted
   `content_ciphertext`, not a bare string — invented for this task since
   nothing upstream defines a response shape. Lets the caller distinguish
   *why* it got what it got (denied vs. manual vs. approved) without
   parsing prose.
3. **`ask()`'s bounded wait (default 5 attempts, 1s apart) rather than a
   blocking indefinite wait or pure fire-and-forget.** PRD doesn't specify
   this. Matches the "simple interval poll, no websockets" scope
   constraint — if the recipient hasn't answered within the budget,
   `ask()` returns `{"status": "pending", ...}`; the caller's own
   already-running poll loop (`PendingResponseRegistry`) will still
   deliver the answer later, just not within that one tool call.
4. **`sign_bytes`/`verify_bytes` added to `identity/`** rather than
   packing grant fields into `RequestPayload` — your explicit choice
   over the alternative (repurposing `RequestPayload`'s fields), raised
   as an AskUserQuestion during this task.
5. **Grant canonical encoding duplicated in `agent/wiring/local_state.py`**,
   not imported from `registry/services/grant_payload.py` — `agent/` and
   `registry/` are separate deployable processes (CLAUDE.md §3)
   communicating only over HTTP; agent/ must not depend on registry/'s
   source at runtime. Same category of necessary duplication as
   `registry/services/canonical_payload.py` already is for identity/'s
   Rust format.
6. **`process_incoming_ask` silently drops a request that fails local
   re-verification** (returns without responding) rather than sending an
   explicit rejection response. Matches "fails closed" — no signed
   channel exists to a sender whose signature didn't verify, so there is
   nothing safe to sign a rejection with in reply.
