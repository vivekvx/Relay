# Relay — Agent Operating Instructions

## 1. Project summary

Relay is a peer-to-peer consultation primitive for coding agents: it lets
your Claude Code agent ask a specific person's agent a question and get
back only a pre-approved, explicitly human-marked-shareable slice of their
context — never a raw memory dump, never an LLM-inferred disclosure.
Current stage: pre-implementation. `PRD.md` exists; no code has been
written yet.

## 2. Non-negotiable invariants

Pulled from `PRD.md` §5. Never violate these while writing code, at any
layer, for any reason (including "just for a quick prototype"):

- Capsule scope resolution MUST happen before any LLM call, in
  deterministic code. It is never an LLM decision, never a prompt, never
  something the model is asked to "judge."
- No capsule content, query text, or response text may ever be stored,
  cached, or logged by the hosted registry. The registry stores only
  identity, routing, and audit **metadata** (who queried whom, when,
  which grant/approval ID was used) — never content.
- Every cross-agent request MUST be signed. Unsigned or invalid-signature
  requests are rejected before scope resolution, before any capsule
  lookup, before anything else runs.
- Only pre-written, explicitly `shareable: true`-marked documents can ever
  become a capsule. Live conversation content, chat history, or raw
  working memory are never eligible, full stop — no code path may read
  from an active conversation buffer to assemble a capsule.
- Any sender/topic-scope pair without an existing standing grant MUST go
  through live human approval (terminal UI). Never auto-approve a new
  sender or new scope.
- Every signed request carries a nonce + timestamp; replayed or
  expired-window requests are rejected before scope resolution.
- An unanswered Approval Request MUST always resolve to auto-deny on
  expiry — never silently grant access. The approver configures
  `expiry_duration` (default 5 hours); the auto-deny-on-expiry behavior
  itself is not configurable.
- Revoking a standing grant takes effect immediately: grant validity MUST
  be re-checked at the moment of capsule load, not only at request
  intake.
- Relay must never import, submodule, or otherwise depend on the vaultd
  repo — they are separate projects by design. Identity/signing is
  Relay's own standalone Rust module, modeled on vaultd's architectural
  pattern but independent code and repo.

If a change you're about to make would touch any of the above, stop and
re-read `PRD.md` §5 before proceeding — these are the six attack vectors
Relay exists to defuse.

## 3. Architecture boundaries

This is a single repository — not a monorepo of independently versioned
packages, not multiple repos. The registry, agent, and identity module
all live in this one repo, versioned together.

Two hard sides, and code must be organized so the split is structurally
obvious (a `registry/` vs `agent/` vs `identity/` folder split within
this single repo — see the scaffolded structure):

- **Local (each person's machine):** Relay MCP server/client, identity/
  signing (own standalone Rust module, pattern modeled on vaultd but
  independent code — never a dependency on the vaultd repo itself),
  capsule store (markdown + SQLite/FTS5), deterministic scope resolver,
  terminal approval UI, local audit log. All capsule content and private
  keys live here and never leave.
- **Hosted registry:** FastAPI + PostgreSQL on Render. Handle→endpoint
  resolution, public key storage, signed-request routing, routing/audit
  metadata only. It must be structurally incapable of reading capsule
  content — don't add a code path that would let it.

Never let a "just for now" shortcut move capsule content, private keys,
or unredacted query/response text across this boundary.

## 4. Tech stack lock-in

Fixed decisions from `PRD.md` §7 — do not introduce new frameworks,
databases, or infra without raising it back to the human first. This
project already had that conversation:

- MCP server: Python, official MCP SDK.
- Identity/signing: own standalone Rust module within the Relay repo —
  pattern modeled on vaultd's proven daemon/key-storage approach, but
  fully independent code and repo. Never a dependency, submodule, or
  fork of vaultd.
- Hosted registry: FastAPI + PostgreSQL, deployed on Render.
- Capsule store: local markdown + SQLite/FTS5.
- Approval UI: terminal-first — the actual chosen interface, not a
  placeholder pending a future web app.
- No Redis, no message queue, no alternative language substitutions — a
  Postgres-backed counter is the actual chosen design for rate limiting
  at this scale, not a stopgap.

No Redis, no new DB engine, no alternative signing library, no swapping
FastAPI/Postgres for something else, no adding a web framework for the
approval UI. If you think one of these is needed, ask first.

## 5. Coding conventions

- **Python (MCP server, registry):** FastAPI + Pydantic, service-layer
  separation — consistent with how MandateCheck is built. No fat route
  handlers; routes call into service functions, services call into the
  deterministic resolver/data layer.
- **Rust (identity module):** follow vaultd's proven daemon/binary split
  conventions as a pattern reference, but this is fresh, independent
  code owned entirely by the Relay repo — do not import, submodule, or
  otherwise depend on the vaultd repo itself.
- **General:** deterministic, security-critical logic (scope resolution,
  signature verification, grant/approval checks) must be isolated from,
  and never dependent on, LLM output — same clean-architecture instinct
  as Vivek's other projects (MandateCheck, Whiskr, Candor). The LLM
  consumes the resolver's output; it never feeds back into what the
  resolver decides.

## 6. Out of scope

Per `PRD.md` §8 — these are final architectural decisions, not phased
deferrals:

- No peer-to-peer transport — the centralized registry is the permanent
  design.
- No VerifiedAgent — a separate, related-but-distinct product idea, not
  a Relay feature at any stage.

Excerpt-level redaction, fixed-counter rate limiting, and terminal-first
approval are all in scope and already decided (`PRD.md` §8) — do not
treat them as future work or build a lesser stand-in for them.

## 7. Reference documents

`idea.md` and `PRD.md` are the sources of truth. If a design question
comes up mid-implementation — data model detail, security requirement
interpretation, scope boundary — re-read the relevant section of
`PRD.md` (and `idea.md` if `PRD.md` doesn't resolve it) rather than
inventing a new answer. If neither resolves it, it's an open question —
check `PRD.md` §9 first, and if it's genuinely new, raise it with the
human before deciding unilaterally.
