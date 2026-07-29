//! Test suite for keygen, storage, signing, and verification. Proves
//! the properties listed in the task: valid triples verify; tampered
//! payload fails; wrong-payload-same-signature fails; expired
//! timestamp fails; malformed/missing nonce fails; wrong public key
//! fails; private key material never appears in Debug output.

use crate::encryption::{decrypt, encrypt, export_encryption_public_key_hex, generate_encryption_keypair};
use crate::keygen::{export_public_key_hex, generate_keypair};
use crate::payload::RequestPayload;
use crate::signing::{sign_bytes, sign_payload};
use crate::storage::KeyStore;
use crate::verification::{verify_bytes, verify_payload, VerificationError, DEFAULT_MAX_REQUEST_AGE_SECS};

const NOW: u64 = 1_800_000_000;
const VALID_NONCE: &str = "0123456789abcdef0123456789abcdef";

fn sample_payload() -> RequestPayload {
    RequestPayload {
        sender: "vivek".to_string(),
        recipient: "rohan".to_string(),
        request_type: "ask".to_string(),
        timestamp: NOW,
        nonce: VALID_NONCE.to_string(),
    }
}

#[test]
fn valid_signature_verifies_successfully() {
    let (private_key, public_key) = generate_keypair();
    let payload = sample_payload();
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let verified = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS)
        .expect("valid signature/payload/pubkey must verify");

    assert_eq!(verified.sender, "vivek");
    assert_eq!(verified.nonce, VALID_NONCE);
    assert_eq!(verified.timestamp, NOW);
}

#[test]
fn tampered_payload_byte_fails_verification() {
    let (private_key, public_key) = generate_keypair();
    let payload = sample_payload();
    let (mut bytes, signature) = sign_payload(&private_key, &payload);

    // Flip a single byte inside the already-signed buffer.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;

    let result = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS);
    assert_eq!(result.unwrap_err(), VerificationError::InvalidSignature);
}

#[test]
fn signature_valid_for_one_payload_rejected_against_a_different_payload() {
    // Exercises the exact risk in the task: verify against the ACTUAL
    // received bytes, not a re-serialized/different claimed payload.
    let (private_key, public_key) = generate_keypair();
    let payload_a = sample_payload();
    let mut payload_b = sample_payload();
    payload_b.request_type = "grant".to_string();

    let (_bytes_a, signature_a) = sign_payload(&private_key, &payload_a);
    let bytes_b = payload_b.to_canonical_bytes();

    let result = verify_payload(
        &bytes_b,
        &signature_a,
        &public_key,
        NOW,
        DEFAULT_MAX_REQUEST_AGE_SECS,
    );
    assert_eq!(result.unwrap_err(), VerificationError::InvalidSignature);
}

#[test]
fn expired_timestamp_fails_verification() {
    let (private_key, public_key) = generate_keypair();
    let mut payload = sample_payload();
    payload.timestamp = NOW - DEFAULT_MAX_REQUEST_AGE_SECS - 1;
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let result = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS);
    assert_eq!(result.unwrap_err(), VerificationError::ExpiredOrFutureTimestamp);
}

#[test]
fn future_timestamp_beyond_skew_fails_verification() {
    let (private_key, public_key) = generate_keypair();
    let mut payload = sample_payload();
    payload.timestamp = NOW + DEFAULT_MAX_REQUEST_AGE_SECS + 1;
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let result = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS);
    assert_eq!(result.unwrap_err(), VerificationError::ExpiredOrFutureTimestamp);
}

#[test]
fn malformed_nonce_fails_verification() {
    let (private_key, public_key) = generate_keypair();
    let mut payload = sample_payload();
    payload.nonce = "too-short".to_string();
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let result = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::MalformedPayload(_)
    ));
}

#[test]
fn empty_nonce_fails_verification() {
    let (private_key, public_key) = generate_keypair();
    let mut payload = sample_payload();
    payload.nonce = String::new();
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let result = verify_payload(&bytes, &signature, &public_key, NOW, DEFAULT_MAX_REQUEST_AGE_SECS);
    assert!(matches!(
        result.unwrap_err(),
        VerificationError::MalformedPayload(_)
    ));
}

#[test]
fn wrong_public_key_fails_verification() {
    let (private_key, _public_key) = generate_keypair();
    let (_other_private_key, other_public_key) = generate_keypair();
    let payload = sample_payload();
    let (bytes, signature) = sign_payload(&private_key, &payload);

    let result = verify_payload(
        &bytes,
        &signature,
        &other_public_key,
        NOW,
        DEFAULT_MAX_REQUEST_AGE_SECS,
    );
    assert_eq!(result.unwrap_err(), VerificationError::InvalidSignature);
}

#[test]
fn private_key_debug_output_is_always_redacted_regardless_of_content() {
    // Structural guarantee, not just a spot check: two DIFFERENT keys
    // must produce the IDENTICAL Debug string, proving the impl cannot
    // depend on the key bytes at all (see keygen.rs — it ignores `self`).
    let (key_a, _) = generate_keypair();
    let (key_b, _) = generate_keypair();

    let debug_a = format!("{:?}", key_a);
    let debug_b = format!("{:?}", key_b);

    assert_eq!(debug_a, "PrivateKeyMaterial(REDACTED)");
    assert_eq!(debug_a, debug_b);
}

#[test]
fn public_key_export_is_hex_and_round_trips_identity() {
    let (_private_key, public_key) = generate_keypair();
    let hex = export_public_key_hex(&public_key);
    assert_eq!(hex.len(), 64); // 32 bytes, hex-encoded
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn key_store_round_trips_and_sets_owner_only_permissions() {
    let dir = std::env::temp_dir().join(format!("relay-identity-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.key");
    let store = KeyStore::new(&path);

    let (private_key, public_key) = generate_keypair();
    store.save_private_key(&private_key).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let loaded = store.load_private_key().unwrap();
    assert_eq!(loaded.verifying_key(), public_key);

    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------- encryption (X25519) ----------------------------

#[test]
fn encrypt_then_decrypt_round_trips_plaintext() {
    let (recipient_secret, recipient_public) = generate_encryption_keypair();
    let plaintext = b"how do you handle graceful daemon shutdown in Rust?";

    let ciphertext = encrypt(&recipient_public, plaintext).expect("encryption must succeed");
    let recovered = decrypt(&recipient_secret, &ciphertext).expect("decryption must succeed");

    assert_eq!(recovered, plaintext);
}

#[test]
fn tampered_ciphertext_byte_fails_closed_not_partial_plaintext() {
    let (recipient_secret, recipient_public) = generate_encryption_keypair();
    let plaintext = b"sensitive query content";

    let mut ciphertext = encrypt(&recipient_public, plaintext).expect("encryption must succeed");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    let result = decrypt(&recipient_secret, &ciphertext);
    assert!(result.is_err(), "tampered ciphertext must fail to decrypt, not return garbage plaintext");
}

#[test]
fn decrypt_with_wrong_private_key_fails() {
    let (_recipient_secret, recipient_public) = generate_encryption_keypair();
    let (wrong_secret, _wrong_public) = generate_encryption_keypair();
    let plaintext = b"only the real recipient should read this";

    let ciphertext = encrypt(&recipient_public, plaintext).expect("encryption must succeed");
    let result = decrypt(&wrong_secret, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn encryption_public_key_export_is_hex_and_distinct_from_signing_key() {
    let (_recipient_secret, recipient_public) = generate_encryption_keypair();
    let hex = export_encryption_public_key_hex(&recipient_public);
    assert_eq!(hex.len(), 64);
    assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));

    // Ed25519 and X25519 keys are generated independently — this test
    // documents that they are NOT the same key reused for two purposes
    // (see encryption.rs's module docstring for why that matters).
    let (_signing_key, verifying_key) = generate_keypair();
    let signing_hex = export_public_key_hex(&verifying_key);
    assert_ne!(hex, signing_hex);
}

// ---------------------------- sign_bytes / verify_bytes ----------------------------

#[test]
fn sign_bytes_then_verify_bytes_round_trips() {
    let (private_key, public_key) = generate_keypair();
    let message = b"grantor=rohan;grantee=vivek;capsule=c1";

    let signature = sign_bytes(&private_key, message);
    assert!(verify_bytes(message, &signature, &public_key));
}

#[test]
fn tampered_message_fails_verify_bytes() {
    let (private_key, public_key) = generate_keypair();
    let message = b"grantor=rohan;grantee=vivek;capsule=c1";
    let signature = sign_bytes(&private_key, message);

    let tampered = b"grantor=rohan;grantee=vivek;capsule=c2";
    assert!(!verify_bytes(tampered, &signature, &public_key));
}

#[test]
fn wrong_key_fails_verify_bytes() {
    let (private_key, _public_key) = generate_keypair();
    let (_other_private_key, other_public_key) = generate_keypair();
    let message = b"grantor=rohan;grantee=vivek;capsule=c1";
    let signature = sign_bytes(&private_key, message);

    assert!(!verify_bytes(message, &signature, &other_public_key));
}

// ---------------------- shared canonical-payload test vectors ----------------------

#[test]
fn canonical_encoding_matches_shared_test_vectors() {
    // CARGO_MANIFEST_DIR is identity/ (this crate's root); the shared
    // fixture lives at repo root's test-vectors/, one level up — a
    // deliberate, documented resolution (not another fragile relative
    // walk), since repo root is neutral ground shared by identity/,
    // registry/, agent/, and docs/ (see ARCHITECTURE.md).
    let vectors_json = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../test-vectors/canonical_payload_vectors.json"
    ))
    .expect("shared test-vector file must exist at repo root's test-vectors/");
    let parsed: serde_json::Value = serde_json::from_str(&vectors_json).unwrap();

    let vectors = parsed["vectors"].as_array().expect("vectors must be an array");
    assert!(!vectors.is_empty(), "vector file must not be empty");

    for vector in vectors {
        let sender = vector["sender"].as_str().unwrap().to_string();
        let recipient = vector["recipient"].as_str().unwrap().to_string();
        let request_type = vector["request_type"].as_str().unwrap().to_string();
        let timestamp = vector["timestamp"].as_u64().unwrap();
        let nonce = vector["nonce"].as_str().unwrap().to_string();
        let expected_hex = vector["expected_hex"].as_str().unwrap();
        let name = vector["name"].as_str().unwrap();

        let payload = RequestPayload { sender, recipient, request_type, timestamp, nonce };
        let actual_hex = hex_encode(&payload.to_canonical_bytes());

        assert_eq!(
            actual_hex, expected_hex,
            "vector {:?} did not match: identity/'s canonical encoding has drifted from the shared fixture",
            name
        );
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
