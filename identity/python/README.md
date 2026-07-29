# identity/python — PyO3 bridge

The real Python-callable interface to `identity/`'s Rust crate. A thin
`pyo3` wrapper crate (`relay-identity-py`, output module name
`relay_identity`) — it calls straight into the existing, already-tested
`relay-identity` lib crate via a path dependency (`../`). No signing,
verification, encryption, or decryption logic is reimplemented here.

This is now the one real bridge Python components should use — not a
model for `registry/`'s existing duplicated Python reimplementation
(`registry/services/canonical_payload.py` +
`registry/services/signature_verifier.py`), which is a separate,
disclosed follow-up (see `registry/ARCHITECTURE.md` judgment call #1),
untouched by this task.

## Build

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install maturin pytest
maturin develop --release   # builds identity/'s Rust crate + this bridge, installs into the venv
```

## Test

```bash
pytest tests -q
```

23 tests, each mirroring a case from `identity/src/tests.rs` by name
(see the comment at the top of `tests/test_bindings.py`) — proving the
bridge doesn't change behavior, not just that it compiles. `cargo test`
in `identity/` (the crate this bridge depends on) is unaffected — its
16 tests still pass unmodified, confirmed after this task.

## API surface

Module `relay_identity`:

- `generate_keypair() -> (PrivateKeyMaterial, public_key_hex: str)`
- `PrivateKeyMaterial.verifying_key_hex() -> str` — the only accessor;
  no method returns raw key bytes. `repr()`/`str()` always return
  `"PrivateKeyMaterial(REDACTED)"`, content-independent (see
  `test_private_key_repr_and_str_are_always_redacted_regardless_of_content`,
  `test_private_key_material_exposes_no_raw_byte_accessor`).
- `KeyStore(path: str)` — `.save_private_key(key)`, `.load_private_key()
  -> PrivateKeyMaterial`, `.exists() -> bool`. Same owner-only (`0o600`)
  file permission discipline as the Rust `KeyStore`.
- `RequestPayload(sender, recipient, request_type, timestamp, nonce)` —
  1:1 field mapping to `relay_identity::RequestPayload` (Rust).
- `sign_payload(key, payload) -> (canonical_bytes: bytes, signature:
  bytes)`
- `verify_payload(received_bytes, signature, public_key_hex, now,
  max_age_secs) -> VerifiedRequest` — raises `InvalidSignature`,
  `MalformedPayload`, or `ExpiredOrFutureTimestamp` (all subclasses of
  `VerificationError`), mirroring the Rust enum's three variants
  exactly.
- `generate_encryption_keypair() -> (EncryptionKeyMaterial,
  public_key_hex: str)`
- `EncryptionKeyMaterial.public_key_hex() -> str` — same no-raw-bytes,
  always-redacted-repr discipline as `PrivateKeyMaterial`.
- `EncryptionKeyStore(path: str)` — same shape as `KeyStore`.
- `encrypt(recipient_public_key_hex: str, plaintext: bytes) -> bytes`
  — raises `EncryptError` on failure.
- `decrypt(key: EncryptionKeyMaterial, ciphertext: bytes) -> bytes` —
  raises `DecryptError`; fails closed on any tampering (proven by
  `test_tampered_ciphertext_byte_fails_closed_not_partial_plaintext`).

Public keys cross the boundary as hex `str` (not a Python wrapper
class for `VerifyingKey`/`EncryptionPublicKey`) — an ergonomic choice,
not a behavior change: every Rust function that needs a public key is
still called with the real decoded key type internally
(`verify_payload`/`encrypt` decode the hex back to
`VerifyingKey`/`EncryptionPublicKey` before calling into
`relay-identity`).

## Judgment calls

1. **Public keys as hex strings, not wrapper classes.** Simpler
   Python-side ergonomics (registry/local storage already deal in hex
   anyway — see `identities.public_key_hex` in `registry/db/schema.sql`)
   at the cost of not mirroring `VerifyingKey`/`EncryptionPublicKey` as
   distinct Python types. The actual verification/encryption math is
   unchanged either way — flagging the shape choice, not a behavior
   gap.
2. **`abi3-py310` (stable ABI, Python ≥3.10)** rather than pinning to
   the exact interpreter version — the wheel built by `maturin develop`
   works across CPython 3.10+ without a rebuild per Python version,
   standard PyO3 practice for a bridge meant to be depended on by other
   components.
3. **A local hex encode/decode helper duplicated in this crate**
   (`hex_decode`/`hex_decode_32` in `src/lib.rs`) rather than importing
   a crate for it. This is string-format conversion, not security logic
   — not the kind of "reimplemented identity logic" this task's scope
   warns against (no signing, verification, or crypto math lives in
   it).
4. **One extra Python-boundary-specific test not in the Rust suite**
   (`test_malformed_and_missing_signature_bytes_are_rejected_not_crash`)
   — Rust's `Signature::from_bytes` takes a fixed `[u8; 64]` at the type
   level, so a wrong-length signature is a compile-time-shaped
   non-issue there; over the Python boundary, signature bytes arrive
   untyped, so this shape check is new *plumbing*, not new *security*
   logic, and is worth a test since it's bridge-specific surface area.
