# Proves the PyO3 bridge faithfully surfaces identity/src/'s existing,
# already-tested behavior — not a reimplementation. Every test here has
# a direct counterpart in identity/src/tests.rs; case names below
# reference the Rust test they mirror.

from __future__ import annotations

import json
import os
import stat
import tempfile

import pytest

import relay_identity as ri

NOW = 1_800_000_000
MAX_AGE = 300
VALID_NONCE = "0123456789abcdef0123456789abcdef"


def sample_payload(**overrides):
    fields = dict(
        sender="vivek",
        recipient="rohan",
        request_type="ask",
        timestamp=NOW,
        nonce=VALID_NONCE,
    )
    fields.update(overrides)
    return ri.RequestPayload(**fields)


def flip_last_byte(b: bytes) -> bytes:
    ba = bytearray(b)
    ba[-1] ^= 0x01
    return bytes(ba)


# --- signing / verification (mirrors identity/src/tests.rs) ---------------


def test_valid_signature_verifies_successfully():
    private_key, public_key_hex = ri.generate_keypair()
    payload = sample_payload()
    canonical_bytes, signature = ri.sign_payload(private_key, payload)

    verified = ri.verify_payload(canonical_bytes, signature, public_key_hex, NOW, MAX_AGE)

    assert verified.sender == "vivek"
    assert verified.nonce == VALID_NONCE
    assert verified.timestamp == NOW


def test_tampered_payload_byte_fails_verification():
    private_key, public_key_hex = ri.generate_keypair()
    canonical_bytes, signature = ri.sign_payload(private_key, sample_payload())
    tampered = flip_last_byte(canonical_bytes)

    with pytest.raises(ri.InvalidSignature):
        ri.verify_payload(tampered, signature, public_key_hex, NOW, MAX_AGE)


def test_signature_valid_for_one_payload_rejected_against_a_different_payload():
    private_key, public_key_hex = ri.generate_keypair()
    payload_a = sample_payload()
    payload_b = sample_payload(request_type="grant")

    bytes_a, signature_a = ri.sign_payload(private_key, payload_a)
    bytes_b, _ = ri.sign_payload(private_key, payload_b)
    assert bytes_a != bytes_b

    with pytest.raises(ri.InvalidSignature):
        ri.verify_payload(bytes_b, signature_a, public_key_hex, NOW, MAX_AGE)


def test_expired_timestamp_fails_verification():
    private_key, public_key_hex = ri.generate_keypair()
    payload = sample_payload(timestamp=NOW - MAX_AGE - 1)
    canonical_bytes, signature = ri.sign_payload(private_key, payload)

    with pytest.raises(ri.ExpiredOrFutureTimestamp):
        ri.verify_payload(canonical_bytes, signature, public_key_hex, NOW, MAX_AGE)


def test_future_timestamp_beyond_skew_fails_verification():
    private_key, public_key_hex = ri.generate_keypair()
    payload = sample_payload(timestamp=NOW + MAX_AGE + 1)
    canonical_bytes, signature = ri.sign_payload(private_key, payload)

    with pytest.raises(ri.ExpiredOrFutureTimestamp):
        ri.verify_payload(canonical_bytes, signature, public_key_hex, NOW, MAX_AGE)


def test_malformed_nonce_fails_verification():
    private_key, public_key_hex = ri.generate_keypair()
    payload = sample_payload(nonce="too-short")
    canonical_bytes, signature = ri.sign_payload(private_key, payload)

    with pytest.raises(ri.MalformedPayload):
        ri.verify_payload(canonical_bytes, signature, public_key_hex, NOW, MAX_AGE)


def test_empty_nonce_fails_verification():
    private_key, public_key_hex = ri.generate_keypair()
    payload = sample_payload(nonce="")
    canonical_bytes, signature = ri.sign_payload(private_key, payload)

    with pytest.raises(ri.MalformedPayload):
        ri.verify_payload(canonical_bytes, signature, public_key_hex, NOW, MAX_AGE)


def test_wrong_public_key_fails_verification():
    private_key, _public_key_hex = ri.generate_keypair()
    _other_private_key, other_public_key_hex = ri.generate_keypair()
    canonical_bytes, signature = ri.sign_payload(private_key, sample_payload())

    with pytest.raises(ri.InvalidSignature):
        ri.verify_payload(canonical_bytes, signature, other_public_key_hex, NOW, MAX_AGE)


def test_malformed_and_missing_signature_bytes_are_rejected_not_crash():
    # Not in the Rust suite (Signature::from_bytes there takes a fixed
    # [u8; 64] at the type level, so this shape error is unreachable in
    # Rust) — this is a Python-boundary-specific case: signature arrives
    # as untyped bytes over the bridge, so wrong length must be a clean
    # error, not a panic.
    private_key, public_key_hex = ri.generate_keypair()
    canonical_bytes, _signature = ri.sign_payload(private_key, sample_payload())

    with pytest.raises(ValueError):
        ri.verify_payload(canonical_bytes, b"too-short", public_key_hex, NOW, MAX_AGE)


def test_malformed_public_key_hex_is_rejected_not_crash():
    private_key, _public_key_hex = ri.generate_keypair()
    canonical_bytes, signature = ri.sign_payload(private_key, sample_payload())

    with pytest.raises(ValueError):
        ri.verify_payload(canonical_bytes, signature, "not-hex-at-all", NOW, MAX_AGE)


# --- redaction (private_key_debug_output_is_always_redacted_regardless_of_content) --


def test_private_key_repr_and_str_are_always_redacted_regardless_of_content():
    key_a, _ = ri.generate_keypair()
    key_b, _ = ri.generate_keypair()

    assert repr(key_a) == "PrivateKeyMaterial(REDACTED)"
    assert repr(key_a) == repr(key_b)
    assert str(key_a) == "PrivateKeyMaterial(REDACTED)"


def test_private_key_material_exposes_no_raw_byte_accessor():
    # Structural, not just behavioral: no method/attribute on the class
    # can hand raw key bytes back to Python at all.
    key, _ = ri.generate_keypair()
    public_names = [n for n in dir(key) if not n.startswith("_")]
    assert public_names == ["verifying_key_hex"]


def test_encryption_key_repr_and_str_are_always_redacted_regardless_of_content():
    key_a, _ = ri.generate_encryption_keypair()
    key_b, _ = ri.generate_encryption_keypair()

    assert repr(key_a) == "EncryptionKeyMaterial(REDACTED)"
    assert repr(key_a) == repr(key_b)
    assert str(key_a) == "EncryptionKeyMaterial(REDACTED)"


def test_encryption_key_material_exposes_no_raw_byte_accessor():
    key, _ = ri.generate_encryption_keypair()
    public_names = [n for n in dir(key) if not n.startswith("_")]
    assert public_names == ["public_key_hex"]


# --- public key export (public_key_export_is_hex_and_round_trips_identity) --


def test_public_key_export_is_hex_of_correct_length():
    _private_key, public_key_hex = ri.generate_keypair()
    assert len(public_key_hex) == 64
    assert all(c in "0123456789abcdef" for c in public_key_hex)


# --- key store round trip (key_store_round_trips_and_sets_owner_only_permissions) --


def test_key_store_round_trips_and_sets_owner_only_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.key")
        store = ri.KeyStore(path)

        private_key, public_key_hex = ri.generate_keypair()
        store.save_private_key(private_key)

        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

        loaded = store.load_private_key()
        assert loaded.verifying_key_hex() == public_key_hex


def test_key_store_exists_reflects_file_presence():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.key")
        store = ri.KeyStore(path)
        assert store.exists() is False

        private_key, _ = ri.generate_keypair()
        store.save_private_key(private_key)
        assert store.exists() is True


# --- encryption (X25519 sealed box) ----------------------------------------


def test_encrypt_then_decrypt_round_trips_plaintext():
    secret, public_hex = ri.generate_encryption_keypair()
    plaintext = b"how do you handle graceful daemon shutdown in Rust?"

    ciphertext = ri.encrypt(public_hex, plaintext)
    recovered = ri.decrypt(secret, ciphertext)

    assert recovered == plaintext


def test_tampered_ciphertext_byte_fails_closed_not_partial_plaintext():
    secret, public_hex = ri.generate_encryption_keypair()
    ciphertext = ri.encrypt(public_hex, b"sensitive query content")
    tampered = flip_last_byte(ciphertext)

    with pytest.raises(ri.DecryptError):
        ri.decrypt(secret, tampered)


def test_decrypt_with_wrong_private_key_fails():
    _recipient_secret, recipient_public_hex = ri.generate_encryption_keypair()
    wrong_secret, _wrong_public_hex = ri.generate_encryption_keypair()
    ciphertext = ri.encrypt(recipient_public_hex, b"only the real recipient should read this")

    with pytest.raises(ri.DecryptError):
        ri.decrypt(wrong_secret, ciphertext)


def test_encryption_public_key_export_is_hex_and_distinct_from_signing_key():
    _secret, public_hex = ri.generate_encryption_keypair()
    assert len(public_hex) == 64
    assert all(c in "0123456789abcdef" for c in public_hex)

    _signing_key, signing_public_hex = ri.generate_keypair()
    assert public_hex != signing_public_hex


def test_encryption_key_store_round_trips_and_sets_owner_only_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.enc.key")
        store = ri.EncryptionKeyStore(path)

        secret, public_hex = ri.generate_encryption_keypair()
        store.save_private_key(secret)

        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

        loaded = store.load_private_key()
        assert loaded.public_key_hex() == public_hex


# --- sign_bytes / verify_bytes (mirrors sign_bytes_then_verify_bytes_round_trips etc.) -----


def test_sign_bytes_then_verify_bytes_round_trips():
    private_key, public_key_hex = ri.generate_keypair()
    message = b"grantor=rohan;grantee=vivek;capsule=c1"

    signature = ri.sign_bytes(private_key, message)
    assert ri.verify_bytes(message, signature, public_key_hex) is True


def test_tampered_message_fails_verify_bytes():
    private_key, public_key_hex = ri.generate_keypair()
    message = b"grantor=rohan;grantee=vivek;capsule=c1"
    signature = ri.sign_bytes(private_key, message)

    tampered = b"grantor=rohan;grantee=vivek;capsule=c2"
    assert ri.verify_bytes(tampered, signature, public_key_hex) is False


def test_wrong_key_fails_verify_bytes():
    private_key, _public_key_hex = ri.generate_keypair()
    _other_private_key, other_public_key_hex = ri.generate_keypair()
    message = b"grantor=rohan;grantee=vivek;capsule=c1"
    signature = ri.sign_bytes(private_key, message)

    assert ri.verify_bytes(message, signature, other_public_key_hex) is False


def test_verify_bytes_rejects_malformed_signature_length_not_crash():
    _private_key, public_key_hex = ri.generate_keypair()
    with pytest.raises(ValueError):
        ri.verify_bytes(b"message", b"too-short", public_key_hex)


# --- shared canonical-payload test vectors (canonical_encoding_matches_shared_test_vectors) --


def test_canonical_encoding_matches_shared_test_vectors():
    # Repo-root fixture, same file identity/src/tests.rs and
    # registry/tests/test_registry.py both load — proves the bridge's
    # sign_payload produces byte-identical canonical encoding to the
    # real Rust implementation, not a Python-side reimplementation of
    # the format.
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    vectors_path = os.path.join(repo_root, "test-vectors", "canonical_payload_vectors.json")
    with open(vectors_path) as f:
        vectors = json.load(f)["vectors"]

    assert vectors, "vector file must not be empty"

    # sign_payload always signs with a real key; the vectors only assert
    # canonical byte encoding, so use a throwaway key and check the
    # canonical_bytes half of sign_payload's return value.
    private_key, _ = ri.generate_keypair()

    for vector in vectors:
        payload = ri.RequestPayload(
            vector["sender"],
            vector["recipient"],
            vector["request_type"],
            vector["timestamp"],
            vector["nonce"],
        )
        canonical_bytes, _signature = ri.sign_payload(private_key, payload)
        actual_hex = canonical_bytes.hex()
        assert actual_hex == vector["expected_hex"], (
            f"vector {vector['name']!r} did not match: PyO3 bridge's canonical "
            "encoding has drifted from the shared fixture"
        )
