# identity/ — Architecture

Own standalone Rust module, within the Relay repo. Models vaultd's
architectural pattern (local daemon, local key storage, no network
exposure of raw keys) but does not import, submodule, fork, or share a
codebase with vaultd (CLAUDE.md §2, §4). This document is the module's
own design record — see PRD.md §4.2 "Identity layer" and §5 (R2, R6)
for the product-level requirements this implements.

## What this module does

1. Generates an Ed25519 keypair (`keygen.rs`).
2. Stores the private key on local disk with owner-only file
   permissions (`storage.rs`).
3. Signs an outgoing request payload (`signing.rs`), over a canonical
   byte encoding (`payload.rs`).
4. Verifies an incoming signed request (`verification.rs`): signature
   validity, timestamp freshness, nonce well-formedness.
5. Exports the public key in a registration-ready format (`keygen.rs`).
6. Generates a *separate* X25519 keypair for encryption
   (`encryption.rs`), stored with the same owner-only file permission
   discipline as the signing key.
7. Encrypts/decrypts content for a specific recipient (`encryption.rs`)
   — this is what lets query text travel through the registry as
   opaque ciphertext (see registry/ARCHITECTURE.md's now-closed gap).

## Why two keypairs, not one reused for both purposes

Ed25519 (signing) and X25519 (encryption) are generated and stored
completely independently. Reusing a single Ed25519 signing key as an
encryption key (or vice versa) is a known cryptographic footgun —
signing and Diffie-Hellman key exchange can interact in ways that leak
information about the key or enable cross-protocol attacks; this is
exactly the risk ed25519-dalek's own documentation warns against for
`to_scalar`/X25519-conversion use cases. Keeping them as two separate
keypairs, each generated with its own CSPRNG call and stored in its own
file, avoids that entire risk class structurally rather than relying on
careful usage to avoid a documented pitfall.

## What this module defends against, and what it does not

**Local key storage (`storage.rs`):**
- Defends against: another unprivileged local account, or a process
  running as a different user, reading the key file off disk.
- Does NOT defend against: a compromised or malicious process running
  as the *same* user account (file permissions don't stop that), a
  compromised OS/kernel, physical disk access without full-disk
  encryption, or the user copying the key file elsewhere themselves.
  File permissions are a local-privilege boundary, not a confidentiality
  guarantee against the account owner.
- Windows: no ACL-restriction equivalent is implemented. Real Windows
  support is a real follow-up, not implemented — `create_owner_only_file`
  on non-Unix refuses to write the private key at all (`Unsupported`
  error) rather than writing it unprotected. A loud refusal, not a
  best-effort warning that could go unnoticed, is correct for a
  security-critical module.

**Signature verification (`verification.rs`):**
- Defends against: identity spoofing (PRD.md §5 R2) — a request is
  only accepted if it's signed by the private key matching the claimed
  sender's registered public key. Replay/relay abuse (R6) — every
  request must carry a nonce and a timestamp inside a configurable
  validity window (`DEFAULT_MAX_REQUEST_AGE_SECS`, ±30s, symmetric —
  resolved decision, see PRD.md §5).
- Does NOT defend against: replay of the *same* (sender, nonce) pair
  within that window — this module has no persistence (see "What the
  caller must do" below). It also does not defend against a
  compromised private key (if the key itself is stolen, signatures from
  it are indistinguishable from genuine ones — that's what `storage.rs`
  and the OS-level trust boundary are for, not this module).

## Exactly what gets signed: the canonical payload format

Defined in `payload.rs`. Field order (fixed): `sender`, `recipient`,
`request_type`, `timestamp`, `nonce`. Each string field is encoded as a
4-byte big-endian length prefix followed by its UTF-8 bytes; `timestamp`
is an 8-byte big-endian unix-seconds integer. Trailing bytes after the
nonce are rejected.

This exists to close a real vulnerability class: naive field
concatenation (`sender + recipient`) is ambiguous — shifting a
character from the end of `sender` to the start of `recipient`
produces a different logical request with an identical concatenated
byte string, so a signature over the concatenation doesn't actually
commit to which fields held which value. Length-prefixing every field
makes the encoding unique per (sender, recipient, request_type,
timestamp, nonce) tuple.

**The verify-what-you-received risk (`verification.rs`):**
`verify_payload` takes the raw bytes that arrived over the wire,
verifies the signature against those exact bytes, and then parses
fields from *that same buffer* — never from an independently
reconstructed/re-serialized copy. If verification checked one buffer
but a caller then trusted fields decoded from a different buffer (e.g.
"verify raw bytes, then re-serialize a parsed struct and act on that
instead"), a signature valid over bytes A could be misattributed to
fields decoded from bytes B. This module's single-buffer,
parse-what-you-verified design structurally rules that out.

## What the calling code (registry / local agent) is responsible for

This module deliberately does NOT do the following — they belong to
whatever calls it:

- **Nonce persistence / replay dedup.** `verify_payload` returns a
  `VerifiedRequest { sender, nonce, timestamp, .. }` tuple. The caller
  (registry or local agent) must check `(sender, nonce)` against its
  own seen-nonce store and reject duplicates within the validity
  window. This module only enforces that a nonce is *present and
  correctly formatted* (32 hex characters) — it holds no history of
  which nonces have been seen, by design (that's registry/agent
  persistence territory, not this module's).
- **Network transport.** No HTTP client, no calls to the registry, no
  code that sends the exported public key anywhere. Registering a
  public key with the hosted registry is a separate task.
- **Daemon wrapping.** This is a library/crate (plus a manual
  `cargo run` smoke-test binary), not a long-running daemon process.
  Whether it eventually runs inside a daemon (matching vaultd's
  pattern) is an open decision for a later task — see "Judgment calls."
- **Capsule/grant/approval awareness.** This module has no concept of
  capsules, grants, or approval requests. Its only job is: generate
  keys, sign payloads, verify payloads.

## Encryption construction (X25519 + sealed box)

`encryption.rs` uses the `crypto_box` crate's "sealed box" functions
(`PublicKey::seal` / `SecretKey::unseal`) — a Rust implementation of
libsodium's `crypto_box_seal`: X25519 ECDH key agreement + XSalsa20-
Poly1305 AEAD. This module calls that construction; it does not
implement ECDH or the AEAD cipher itself, per the task's explicit
instruction not to hand-roll key derivation or the AEAD construction.

Sealed box specifically (not the authenticated `SalsaBox`/`ChaChaBox`
variant, which needs a sender keypair) because `encrypt()`'s contract
only takes the recipient's public key — no sender private key is
required. Sender authenticity for the overall request is already
established by the Ed25519 signature on the outer envelope (§ above);
the encryption layer's only job is confidentiality, not a second
authentication mechanism. `crypto_box::seal` generates a fresh
ephemeral X25519 keypair per call internally and prepends the ephemeral
public key to the ciphertext, so any registered recipient can always
decrypt without a prior key-exchange round trip.

**Fails closed, structurally:** `decrypt()` returns `Result`, and the
only way to get an `Ok` is for the underlying AEAD tag verification to
succeed. A single flipped ciphertext byte breaks the Poly1305
authentication tag check inside `crypto_box`, so `unseal` returns
`Err` — there is no code path in this module that can produce partial
or garbage plaintext on tampering; the `?`-free direct `map_err` in
`decrypt()` means a failure can only ever become `Err(DecryptError)`,
never a plaintext value. Proven by
`tampered_ciphertext_byte_fails_closed_not_partial_plaintext`.

## Judgment calls flagged during this task

1. **Daemon vs. library.** The task explicitly asked me to confirm
   before deciding this needs to run as a daemon. I built it as a plain
   library crate (+ a minimal smoke-test binary), not a daemon — this
   is the conservative reading of "model vaultd's pattern," not a
   decision that it must become a daemon. Flagging for confirmation.
2. **Windows key-file permissions are not implemented.** `storage.rs`
   only restricts permissions on Unix (`0o600`). The non-Unix path now
   refuses outright — returns an `Unsupported` error stating secure
   local key storage isn't implemented for this platform — rather than
   writing an unprotected key file. Implementing a correct Windows ACL
   restriction would need a Windows-specific crate (out of proportion to
   this task's scope, and not explicitly requested) — flagging rather
   than adding it unasked. Real Windows support remains a real
   follow-up, not implemented.
3. **`crypto-common` added as a direct dependency.** `ed25519-dalek`
   3.0's OS-backed key generation is fallible-by-design in this
   dependency generation (`rand` 0.10 / `rand_core` 0.10 moved OS
   randomness to `TryCryptoRng`-only sources, no infallible `OsRng`
   remains). Generating a key requires importing the `Generate` trait
   from `crypto-common` (already a transitive dependency of
   `ed25519-dalek`'s `digest` feature) — this is a trait import, not a
   new capability or new crate in the dependency tree in practice, but
   it is a new *direct* Cargo.toml entry, so flagging it explicitly.
4. **Symmetric clock-skew window.** `verify_payload` rejects a
   timestamp that's either older than `max_age_secs` in the past *or*
   further than `max_age_secs` in the future, using the same constant
   for both directions rather than a separate future-skew constant.
   This wasn't specified either way in PRD.md — a reasonable default,
   flagged in case a tighter future-skew bound is wanted later.
5. **Shared test-vector fixture lives at repo root, `/test-vectors/
   canonical_payload_vectors.json`** — moved there from
   `identity/test-vectors/` in a later fix, specifically because that
   original location made `registry/tests/test_registry.py` reach it
   via a fragile relative walk up and across directories
   (`identity/`-owned path, read from outside `identity/`). Repo root
   is genuinely neutral ground between `identity/`, `registry/`,
   `agent/`, and `docs/` — owned by neither component, so the path each
   test suite resolves it from is a single documented hop from its own
   crate/package root to repo root, not a guess about how many `..`
   segments to walk. Both `identity/src/tests.rs`
   (`CARGO_MANIFEST_DIR/../test-vectors/...`) and
   `registry/tests/test_registry.py`
   (`Path(__file__).resolve().parents[2] / "test-vectors" / ...`) load
   the exact same JSON; any future drift between the two canonical-
   payload implementations still fails loudly in both places.
