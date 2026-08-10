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

## Conversation threading (`relay ask --thread`)

Multi-turn follow-up questions in the same conversation. The core
design question — and its resolution — from the task that built this:

**CASE A (same-scope follow-up)** — every capsule a new question's
`resolver.search_candidates` surfaces is already in the conversation's
approved-scope-set → skip the live approval prompt; answer immediately.
**CASE B (new-scope follow-up)** — the search surfaces at least one
capsule not yet in that set → live approval, but scoped to *only* the
new capsule(s); already-approved ones are never re-prompted.

The only test for A vs. B is `resolver.resolver.split_thread_candidates`
— pure set membership (candidate IDs vs. `approved_capsule_ids`), no
query text involved, same deterministic-before-any-LLM standard as
`resolve_scope` itself (PRD.md §5 R1/R7/R8). `process_incoming_ask` in
`wiring/flows.py` is the only caller; it never compares query text for
"relatedness" — that would be exactly the kind of LLM-adjacent judgment
call this project's non-negotiable invariants forbid.

**Data model** (`wiring/threads.py`): `ThreadRecord` — `thread_id`,
`sender`, `recipient`, `created_at`, `last_activity_at`,
`approved_capsule_ids` (grows only via whole-document approvals — see
below), `messages` (question/answer/outcome log for `relay thread
<id>`). One JSON file per local identity (`ThreadStore`), entirely
local — never synced anywhere.

**Where thread_id travels:** inside the already end-to-end-encrypted
`content_ciphertext` payload, both directions — `{"question":...,
"thread_id":...}` on the way in, an added `"thread_id"` field on the
existing response envelope on the way out. Same channel the response
envelope's `in_reply_to_nonce` already uses. `RequestPayload`'s 5 fixed
signed fields are untouched; no registry-visible field carries a
thread_id. **Resolved decision on the registry hard-boundary question
this task asked to re-examine: the registry needs to know nothing
about threads at all** — not even an opaque routing token — because
message routing already works via sender/recipient handles and the
existing nonce/`in_reply_to_nonce` pairing has no need for a
conversation concept. Zero registry changes were needed for this
feature.

**Only whole-document (`APPROVED_WHOLE`) approvals extend
`approved_capsule_ids`.** An `APPROVED_EXCERPT` approval does NOT — an
approver consenting to share one paragraph must never let a later
follow-up auto-continue into the rest of that same document without
its own approval. This is the one place the accumulation logic is
stricter than "capsule appeared in a decision."

**Thread expiry: 24h since last activity** (`DEFAULT_THREAD_INACTIVITY_
EXPIRY`), independent of any single `ApprovalRequest`'s own 5h
`expiry_duration` — a different kind of expiry for a different kind of
object (a conversation vs. one pending decision). Resolved default for
what happens on expiry: the accumulated `approved_capsule_ids` simply
stop being trusted for auto-continuation (forces a fresh prompt); nothing
is deleted, no thread's identity or message history is wiped. Never a
harder failure mode than "ask again," matching "unresolved must never
silently grant" (CLAUDE.md §2).

**A fresh thread never inherits another thread's approved scope** —
structural, not policy: `thread_id` is the sole key into
`approved_capsule_ids`, generated fresh (same random-hex shape as a
nonce) whenever the caller omits `--thread`/`thread_id`. Two threads
between the same two participants, even asking the identical question,
are two unrelated entries with two empty starting scopes.

**Rate limiting is unaffected by threading** — `rate_limiter.
check_and_record` still runs once per incoming "ask" item, before any
thread lookup, regardless of which thread (if any) the message belongs
to (PRD.md §5 R3).

## Structured pre-ask fields (reason/urgency)

`relay ask` collects two extra fields from the requester before sending
— `reason` ("why do you need this?") and `urgency` ("is this
time-sensitive?") — as distinct fields on the wire (bundled into the
same JSON `content_ciphertext` payload as `question`/`thread_id`), never
concatenated into the question string. `resolver.types.ApprovalRequest`
carries them (`reason: str = ""`, `urgency: str = ""`), and
`approval/render.py`'s `render_request` displays them as their own
labeled lines. Empty defaults render as `"(no reason given)"` /
`"not time-sensitive"` — CLI callers who omit `--reason`/`--urgent` get
prompted interactively (`cli._resolve_reason_and_urgency`); MCP callers
who omit them get the empty-string defaults with no prompt (an MCP tool
call has no interactive terminal to prompt on).

**Structural guarantee, not just a convention:** `resolve_scope` and
`search_candidates` do not take `reason`/`urgency` as parameters at
all — there is no code path by which these fields could reach either
function, so "they never affect what capsules get matched" is true by
the functions' own signatures, not by discipline. Proven at the
resolver level (`resolver/tests/test_resolver.py::
TestStructuredFieldsDontAffectResolution`) and end-to-end
(`agent/tests/test_integration.py::
test_reason_and_urgency_shown_but_dont_change_resolved_capsules`).

## Anti-enumeration guard (PRD.md §5 R3, "salami slicing")

The existing `RateLimiter` bounds volume (N requests/hour) but not
*pattern* — a sender could stay under that limit while still
methodically working through a recipient's entire capsule library one
narrow question at a time. This guard adds visibility for that pattern,
without blocking anything: the human approver still decides every
request; this only tells them when a sender's cumulative footprint
against their library looks broad.

**The exact math** (`resolver.resolver.enumeration_flag`, pure function,
no I/O, no LLM):

```
distinct_capsules_seen = count of distinct capsule IDs actually
    disclosed (APPROVED_WHOLE or APPROVED_EXCERPT outcomes only — never
    MANUAL_ANSWER/DENIED, nothing left this machine there) to this
    sender, by THIS recipient, within a rolling window — default 30
    days (DEFAULT_ENUMERATION_WINDOW), tracked by wiring/disclosure_log.py's
    DisclosureLog, one JSON file per local identity, keyed by sender.

total_capsule_count = len(capsules_by_id) — this recipient's total
    number of shareable-marked capsules (same dict resolve_scope/
    search_candidates already operate on).

flagged = (distinct_capsules_seen / total_capsule_count) > 0.4   # fraction
       OR distinct_capsules_seen > 15                             # absolute
```

Either condition alone is enough to flag — "whichever is more
restrictive." `0.4` (`DEFAULT_ENUMERATION_FRACTION_THRESHOLD`) and `15`
(`DEFAULT_ENUMERATION_ABSOLUTE_THRESHOLD`) are both keyword arguments on
`enumeration_flag`, and both are threaded all the way out to
`process_incoming_ask`'s own keyword arguments
(`enumeration_fraction_threshold`, `enumeration_absolute_threshold`,
`enumeration_window`) — same owner-configurable-default pattern as
`RateLimiter.check_and_record`'s per-call `limit` override and
`process_incoming_ask`'s own `expiry_duration` parameter. A capsule
owner configures their own thresholds the same way they'd configure
either of those: by passing different values into the same call.

**Cumulative footprint is cross-thread by design** — it's `DisclosureLog`,
not `ThreadStore`'s per-conversation `approved_capsule_ids` (a
completely different local store; see "Conversation threading" above).
A sender's footprint keeps growing across every separate thread they
open with this recipient, because the attack this guards against is
exactly "spread the extraction across many separate, individually
unremarkable conversations."

**Only counted when a live decision was actually made** — i.e. only in
the ad hoc branch's `request_approval` call (CASE B or a brand-new
thread's first message). Standing-grant disclosures are NOT counted:
a standing grant is the human's own blanket, ongoing, already-fully-
consented-to sharing arrangement, structurally distinct from the ad hoc
approval flow this guard exists to add visibility into; counting it
would just make every legitimate standing-grant conversation noisy.
CASE A same-scope reuse also isn't re-counted (the capsule was already
recorded the first time it was actually approved) — no double-counting
across follow-ups in one thread.

**Fires as one additional line inside the SAME approval prompt** —
`ApprovalRequest.enumeration_warning: str | None`, computed and
attached before `request_approval` is called, rendered by
`render_request` right after the "Expires in" line when non-`None`.
Never a second prompt, never a block: a normal, low-volume conversation
computes `enumeration_flag(...) == False` and the field stays `None`,
so nothing changes in the approver's experience at all — proven by
`agent/tests/test_integration.py::
test_enumeration_warning_normal_use_never_fires_then_fires_on_broad_pattern`,
which also proves the exact fired wording and numbers for a genuinely
broad pattern (2 of 3 capsules, 66% > 40%).

## Contacts + Relay numbers

`wiring/contacts.py`'s `ContactsStore` maps a local name -> an opaque
**relay number** (never the other person's handle — same trust model as
a phone number). Resolution (`resolve_recipient`) is additive: a saved
contact name resolves through the registry's relay-number lookup to the
real handle; anything not a saved contact passes through unchanged as a
raw handle, so no existing direct-handle call site had to change.

**relay_number is server-generated, never client-supplied**
(`registry/services/identity_service.py::_generate_relay_number`, 8
lowercase hex chars via `secrets.token_hex(4)`, retried up to 5x on the
astronomically unlikely collision). A client choosing its own opaque id
would let it pick something guessable or claim a value someone else
already has — server authority here is the same trust boundary the
registry already holds for `handle` uniqueness itself.

**Registry hard boundary, re-confirmed:** `relay_number` lives in the
same `identities` row as `handle`/public keys — routing metadata, not
content (registry/ARCHITECTURE.md's hard boundary, unchanged). One new
column, one new read-only lookup route
(`GET /identities/by-relay-number/{relay_number}`, mirroring the
existing `GET /identities/{handle}` exactly). No new table, no schema
philosophy change. The new route **must** be registered before the
generic `GET /identities/{handle}` route — FastAPI matches path routes
in registration order, and `{handle}` is a single-segment wildcard that
would otherwise swallow `by-relay-number` as a literal, nonexistent
handle.

## In-chat, both-directions approval (MCP)

`relay_pending_requests` / `relay_respond_to_request` are a new
**interface** onto the existing approval machinery — zero new decision
logic. `relay_pending_requests` is `wiring/flows.py`'s new
`list_pending_approvals_with_candidates`, a read-only formatter that
recomputes `search_candidates` fresh (never a stale snapshot) purely
for display (`match_reason`/`relevant_span`) and returns exactly what
the terminal prompt already shows, as structured JSON.
`relay_respond_to_request` builds a **real** `ApprovalDecision` (the
exact same frozen dataclass `approval/interaction.py`'s terminal picker
constructs, same `__post_init__` invariants) from structured MCP args,
then calls the **exact same** `resolve_pending_approval` the terminal
`relay pending` path uses — that function gained one new optional
`decision` parameter; when supplied, it skips `request_approval`'s
`input()` call and everything after (thread/disclosure bookkeeping,
grant promotion, sending the response) is one shared code path, never
duplicated. `mcp_server.py`'s `_build_decision_from_response_args` is
the only new code, and it only translates args into that decision type
— any decision type/field it can't map unambiguously raises
`ValueError`, surfaced as `{"error": "ambiguous_decision", ...}` so
Claude Code must ask a clarifying question and retry, never guess
(proven by `test_ambiguous_decision_is_rejected_not_guessed`).

**Structural guarantees carried through unchanged:** `resolve_scope`/
`search_candidates` still never receive query text as a scope-deciding
parameter regardless of interface; `ApprovalDecision.__post_init__`
still enforces default-deny-on-ambiguous (the same invariant class as
`approval/interaction.py`'s `_denied()` fallback) whether the decision
came from a terminal picker or from MCP args; the enumeration guard and
thread-scope logic are computed in `process_incoming_ask` itself,
upstream of every interface (terminal, `relay pending`, or this MCP
path) — none of them can see or bypass that computation.

**Design decision on how Paul's Claude Code learns to check (task's
explicit either/or):** option (a) — rely on the existing native
notification (`relay serve`'s headless flow) to alert Paul outside
Claude Code; he returns to a chat and asks something like "check my
relay requests," and Claude Code calls `relay_pending_requests` on
demand. **Option (b) was investigated and explicitly rejected, not
silently skipped:** the MCP SDK actually installed in this repo (`mcp`
2.0.0, low-level `Server`/`ClientSession` API — see this file's
existing "Judgment call" note on which SDK shape this project targets)
exposes no mechanism for a server to proactively push a
message/notification INTO a client's chat session unprompted. The
protocol's server-initiated primitives that do exist (`sampling` —
asking the client to run an LLM completion; the logging/progress
notification types) are not a "wake up and show the user this" channel
— they're either request/response continuations of a call already in
flight, or observability, not unsolicited chat injection. Given no real
mechanism exists in this installed SDK version, (a) is not a
compromise — it is the only structurally available option, and it
composes cleanly with the already-built native notification.

## Observability: trace_id vs nonce correlation

`trace_id` (`wiring/trace.py`) and `nonce` (`wiring/nonce.py`) look
similar (both random hex strings attached to a request) but serve
different, non-overlapping jobs:

- **`nonce`** is part of the signed `RequestPayload` — identity/'s fixed
  wire format. It is cryptographic (replay protection, PRD.md §5 R6) and
  is the one value that travels all the way from the original caller to
  the recipient's process, inside the signed/encrypted request itself.
  It is the only thing that can correlate *across* the two independent
  processes on either side of a `relay ask`.
- **`trace_id`** is pure observability metadata — an unsigned
  `X-Relay-Trace-Id` HTTP header, generated fresh per logical operation
  (one `ask`/`grant`/`revoke`/MCP tool call), never part of any signed
  payload, never read back or verified, never gates any authorization
  decision. It only correlates log lines *within one process's own call
  graph* — the caller's `ask_submitted`/`ask_answered` lines, or the
  registry's `relay_request_received`/`...relayed` lines for that one
  HTTP call.

Because `trace_id` isn't in the signed payload, the recipient's process
never receives the original caller's `trace_id` — there is no field to
carry it. When the recipient's poll loop (`process_incoming_ask`) logs
its own side of the exchange, it generates its own fresh `trace_id` for
that leg. To trace one logical `ask` end-to-end across both machines and
the registry, use `nonce` (already logged as `sender`/`nonce` in the
`pending_relay_queue` row and in the caller's `request_id`/`nonce`
result fields) — `trace_id` is single-process log correlation, `nonce`
is cross-process request identity.

## Network scenario matrix

The registry is reached over HTTPS to a single public host
(`relay-registry.onrender.com`) — there is no LAN-discovery, mDNS, or
local-network-specific code path anywhere in `agent/wiring/registry_client.py`.
That structural fact is what the "same machine / same wifi / different
network / same company" collapse claim rests on: from the client's
perspective, every one of those scenarios is identical HTTP+TLS to the
same public endpoint.

| Scenario | Verified how | Result |
|---|---|---|
| Same machine | Full existing test suite (`agent/tests`, `registry/tests`), real local HTTP against a real Postgres-backed FastAPI app | Directly tested, passing |
| Same WiFi | Not independently testable in this sandbox (no second physical device available). Reasoned: the registry client only ever does `httpx` calls to a public HTTPS host — no LAN/mDNS path exists to behave differently on a shared WiFi network vs. any other network | Reasoned, not empirically tested — **needs a real second device to fully confirm** |
| Different network entirely | `curl https://relay-registry.onrender.com/openapi.json` from this machine returned `200`, `title: "Relay Registry"` — proves the endpoint is publicly routable over the open internet, not reachable only from a specific network. This is reachability proof from **one vantage point**, not a two-human test | Reachability confirmed from this machine; cross-network exchange (one person's agent calling another's) still needs a real second human |
| Same company network (shared/private registry) | Same reasoning as above — nothing in the design requires different handling for a corporate network. **Genuinely untestable here**: a corporate firewall/proxy that blocks Render's IP range or forces TLS interception is a real possible failure mode this sandbox cannot simulate | **Requires a real human on that network (e.g. Nitesh) to confirm** — not asserted as verified |

**Honest summary:** "same machine" is the only row with full empirical
test coverage from this environment. The "different network" row has
partial empirical evidence (one-vantage-point public reachability, via
the `curl` above and the gated `test_openapi_reachable_over_https` live
test). "Same WiFi" and "same company network" are structurally reasoned
from the client's HTTPS-only code path, not independently tested — closing
that loop needs a real second person on a genuinely separate network
(same WiFi and, especially, a company network with its own firewall/proxy
behavior) to run `relay doctor` / send a real `relay ask` and confirm it
behaves identically to the same-machine case.
