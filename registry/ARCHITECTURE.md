# registry/ — Architecture

The hosted registry: the only Relay component that must assume every
incoming request is adversarial, because it's the only component
reachable over the network. See PRD.md §4.2 "System Architecture" and
§5 (Security & Privacy Requirements) for the product-level requirements
this implements.

## The hard boundary (restated)

This component MUST NEVER store, cache, log, or have any code path
capable of receiving: capsule content, raw document/excerpt text, or
private key material.

What actually enforces this, structurally, not just by convention:

- **No column, anywhere in `db/schema.sql`, can hold PLAINTEXT
  document content.** `pending_relay_queue.payload` holds identity's
  canonical byte encoding — five fixed fields (`sender`, `recipient`,
  `request_type`, `timestamp`, `nonce`), nothing else; there is no
  content/query field in that format at all. `pending_relay_queue`
  ALSO now has a `content_ciphertext` column (added in a later task) —
  this closes the previously-disclosed gap on how query text reaches a
  recipient, but it does so by carrying *ciphertext*, never plaintext.
  The registry has no X25519 private key material anywhere, so it
  cannot decrypt that column under any code path — this is structural,
  not a matter of the code simply choosing not to try. See "What
  content_ciphertext is, and isn't" below.
- **Every request body uses `model_config = {"extra": "forbid"}`**
  (Pydantic). An incoming JSON payload with an unexpected extra key
  (e.g. a client mistakenly or maliciously attaching `"content"` or
  `"excerpt"`) is rejected by the framework itself before any handler
  code runs.
- **`identities.public_key_hex` is constrained to exactly 64 lowercase
  hex characters** (32 bytes) at both the Pydantic layer and a
  Postgres `CHECK` constraint. Limitation, disclosed: a private key is
  also 32 bytes, so this shape check cannot distinguish "this is a
  public key" from "this is a private key" — it can only reject things
  that clearly aren't either (arbitrary text, document content, wrong
  length). It is not a defense against someone deliberately submitting
  their private key's hex here; that would be a caller-side mistake
  this module has no way to detect.
- **`relay_service.py`'s `MAX_FIELD_LEN` (128 chars) check** flags any
  of `sender`/`recipient`/`request_type` that's implausibly long as
  `suspicious_payload_content` and rejects it. This is a real but
  limited heuristic: it catches naive misuse (stuffing a paragraph
  into `request_type`), not content hidden via chunking, encoding, or
  splitting across multiple otherwise-valid-length fields. Stated
  plainly: **this is a monitoring signal, not a content-detection
  system.** If this outcome ever fires in production, that's a signal
  something upstream is misbehaving and worth investigating — not a
  case to silently swallow and move on from.

## What `content_ciphertext` is, and isn't

`pending_relay_queue.content_ciphertext` carries query/capsule-adjacent
content, but only ever as bytes already encrypted end-to-end to the
recipient's X25519 public key by the sender's own `identity/` module
(`encryption.rs`'s sealed-box construction) BEFORE the request ever
reaches this component. The registry:

- **Never decrypts it.** It has no private key material of any kind —
  `identities` stores only public keys (both Ed25519 and X25519).
  There is no code path in `registry/` that could decrypt this column
  even if someone wanted it to; the capability simply doesn't exist
  here.
- **Never parses or validates its structure.** `services/relay_service.py`
  only checks its *size* (`MAX_CIPHERTEXT_BYTES`, matching the DB
  `CHECK` constraint) before storing it — a plausibility bound, not
  content inspection. It is stored and relayed byte-for-byte.
- **Only logs its size in the audit trail**, e.g.
  `content_ciphertext_bytes=142` — never the ciphertext itself, and
  obviously never anything about the plaintext it decrypts to.

This is the intended resolution to the gap flagged in the previous
registry task: the registry stays exactly as blind to content as
before; the *sender and recipient* now have a way to move content
through it without the registry ever being in a position to read it.

## Append-only audit log: the actual guarantee level

`db/schema.sql`'s `audit_log_append_only` trigger fires `BEFORE UPDATE
OR DELETE` on `audit_log` and unconditionally raises an exception. This
is enforced **regardless of which DB role or code path issues the
statement** — including the table owner, including a bug in this
codebase that tried to update a row. `services/audit_service.py` only
ever `INSERT`s; the trigger is the backstop, not the only thing
standing between a bug and a mutated audit entry.

**What this does not guarantee:** a Postgres superuser can still `DROP
TRIGGER audit_log_append_only` or `ALTER TABLE ... DISABLE TRIGGER`.
The trigger protects against application-level mutation, not against
someone with DB admin privileges deciding to remove the protection
itself. A stronger production hardening layer — a dedicated
`relay_app` role with `UPDATE`/`DELETE` explicitly `REVOKE`d on
`audit_log`, so even a compromised application connection couldn't
issue a mutating statement in the first place — was **not** built in
this pass (it needs multi-role DB provisioning, which felt like more
setup than this task's scope), and is noted here as a disclosed
follow-up, not a silently-skipped requirement.

## What the resolver (not the registry) is responsible for

Grant storage here (`services/grant_service.py`) is intentionally
"just correct, immediately-consistent storage." `revoke_grant` sets
`revoked_at` to `now()`, queryable immediately. That is the entire
scope of this component's revocation responsibility.

**The registry does NOT enforce grant validity at request time**, and
does not re-implement `agent/resolver/`'s check-at-capsule-load-time
logic (PRD.md §3.1 step 8). That check — re-validating a grant's
`revoked_at`/`expires_at` at the exact moment capsules are loaded into
an LLM's context, not cached from when a request first arrived — runs
locally on the recipient's own machine, inside `agent/resolver/`, which
already has its own tests proving this (`resolve_scope`'s revocation-race
tests). Duplicating that enforcement logic here would create two
sources of truth for the same security-critical decision; this
component's job ends at "store the revocation correctly and
immediately," full stop.

## Approval expiry: on-read check, not a background job

See `services/approval_service.py`'s module docstring for the full
justification. Summary: no scheduler/cron infrastructure has been
decided for this project (CLAUDE.md §4 — no Redis, no message queue),
so a background sweep would be a new moving part introduced only for
this. An on-read check is simpler, needs no new infrastructure, and is
always correct at the moment of access — nothing can ever observe a
`pending` state past its `expires_at`, because any read that finds one
transitions it to `denied` transactionally before returning it.

## Judgment calls flagged during this task

1. **No FFI bridge to `identity/`'s Rust verification code.** The task
   asked to "call into identity's verification logic — do not
   reimplement Ed25519 verification here." `identity/` is a separate
   Rust crate with no Python bindings built (that would need PyO3 or a
   subprocess/IPC bridge — a substantial separate task, not requested
   here). What this component actually does: reimplements the
   *canonical payload byte format* in Python
   (`services/canonical_payload.py`, matching `identity/src/payload.rs`
   field-for-field) and uses the `cryptography` library's Ed25519
   implementation for the actual signature math — a vetted library,
   not hand-rolled crypto, which is the specific thing "do not
   reimplement Ed25519" most plausibly meant. This is a real
   duplication-of-format risk (if `payload.rs`'s format ever changes,
   this file must change in lockstep, with nothing enforcing that at
   compile time) — flagging clearly rather than silently presenting it
   as true code reuse. The drift safeguard for this is the shared
   test-vector fixture at repo root, `/test-vectors/
   canonical_payload_vectors.json` (moved there from
   `identity/test-vectors/` in a later fix, so neither component's
   test suite reaches it via a fragile cross-directory relative walk —
   see identity/ARCHITECTURE.md judgment call #5 for the full
   rationale); `registry/tests/test_registry.py` loads this same file
   and asserts byte-identical output against `identity/`'s Rust suite.
2. **RESOLVED (in a later task):** query/capsule-content now travels
   end-to-end encrypted via `pending_relay_queue.content_ciphertext`
   (identity/'s X25519 sealed-box encryption). See "What
   content_ciphertext is, and isn't" above. This item is left here,
   struck through in spirit, so the history of the gap and its
   resolution stays legible in one place rather than being silently
   deleted.
3. **On-read expiry check over a background job** — see above; stated
   explicitly per the task's "your choice, justify it."
4. **Append-only audit log via trigger only, not a restricted DB
   role.** The trigger is a real structural guarantee against
   application-level mutation; a separate least-privilege DB role is a
   disclosed follow-up, not built in this pass.
5. **Rate limiting and approval-expiry config tables
   (`rate_limit_config`, `approval_expiry_config`)** exist only to
   store the already-decided owner-configurable override (PRD.md §5
   R3, §6) — no new policy knobs were added beyond what was already
   specified as decided.
6. **A `GET /identities/{handle}` read endpoint was added**, not
   explicitly requested by the encryption task (which only mentioned
   updating *registration*). Without it, a sender would have no way to
   ever retrieve a recipient's X25519 public key to encrypt content for
   them — the stored column would be unreachable data. Flagged as an
   addition beyond the letter of that task's instructions, kept to the
   minimum (returns the two public keys, nothing else).
7. **No `ALTER TABLE` migration path for the new `identities` /
   `pending_relay_queue` columns** — `schema.sql`'s `CREATE TABLE IF
   NOT EXISTS` pattern only applies the new columns on a fresh
   database. There is no production registry with real data yet
   (pre-launch), so this is a deliberate YAGNI call, not an oversight —
   a real migration tool (Alembic or hand-written `ALTER TABLE ADD
   COLUMN`) becomes necessary the moment there's a live database to
   evolve without dropping it.
   **Tripwire added (later fix):** `db/migrate.py`'s
   `check_migration_safety` now refuses to run `schema.sql` if any of
   `identities` / `pending_relay_queue` already has rows AND is missing
   the columns added for encryption support
   (`x25519_public_key_hex`, `content_ciphertext`) — it raises
   `MigrationSafetyError` naming the table, row count, and missing
   column(s), and points back at this judgment call by name. This is
   explicitly NOT a migration system: no `ALTER TABLE`, no versioned
   migration files, no rollback. It only turns the dangerous silent
   no-op into a loud refusal. A real migration tool is still the
   unresolved follow-up — this fix does not solve that, it only makes
   sure nobody hits the silent-no-op failure mode by accident before
   one exists.
8. **`MAX_CIPHERTEXT_BYTES` (65536) is a judgment-call default**, not
   specified anywhere in PRD.md — sized generously for short query
   text plus sealed-box overhead (48 bytes: 32-byte ephemeral public
   key + 16-byte Poly1305 tag), not derived from any stated requirement.
