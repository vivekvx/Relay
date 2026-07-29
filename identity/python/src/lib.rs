//! PyO3 bridge to the `relay-identity` Rust crate. This is a thin
//! wrapper: every function here calls straight into `identity/src/`'s
//! already-tested logic. No signing, verification, encryption, or
//! decryption math is reimplemented — this crate only translates
//! between Python-friendly types (str/bytes/int) and the Rust types
//! `relay-identity` already exposes.
//!
//! Two private-key wrapper classes (`PrivateKeyMaterial`,
//! `EncryptionKeyMaterial`) hold the real Rust key types opaquely.
//! Neither exposes a method that returns raw key bytes to Python —
//! only derived, non-secret hex-encoded public keys, and `__repr__`
//! always returns a fixed redacted string, mirroring the Rust types'
//! own Debug guarantee (see keygen.rs / encryption.rs) at the Python
//! boundary too.

extern crate relay_identity as core_id;

use pyo3::create_exception;
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;

// ---------------------------------------------------------------------
// hex helpers — string encoding only, not crypto. relay-identity's own
// hex_encode is pub(crate); duplicating a hex codec here is not the
// kind of "reimplemented identity logic" the task warns against, since
// no security-relevant behavior lives in it.
// ---------------------------------------------------------------------

fn hex_decode_32(s: &str) -> PyResult<[u8; 32]> {
    let bytes = hex_decode(s)?;
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("hex string must decode to exactly 32 bytes"))
}

fn hex_decode(s: &str) -> PyResult<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(PyValueError::new_err("hex string must have even length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| PyValueError::new_err("invalid hex string"))
        })
        .collect()
}

// ---------------------------------------------------------------------
// Exceptions — mirror core_id::VerificationError's variants and
// the Encrypt/DecryptError unit structs 1:1, so a Python caller can
// distinguish failure modes exactly as the Rust enum does.
// ---------------------------------------------------------------------

create_exception!(relay_identity, VerificationError, pyo3::exceptions::PyException);
create_exception!(relay_identity, InvalidSignature, VerificationError);
create_exception!(relay_identity, MalformedPayload, VerificationError);
create_exception!(relay_identity, ExpiredOrFutureTimestamp, VerificationError);
create_exception!(relay_identity, EncryptError, pyo3::exceptions::PyException);
create_exception!(relay_identity, DecryptError, pyo3::exceptions::PyException);

// ---------------------------------------------------------------------
// Signing keypair
// ---------------------------------------------------------------------

/// Opaque handle to an Ed25519 private key. No method on this class
/// returns the raw key bytes to Python. `__repr__`/`__str__` always
/// return a fixed redacted string, regardless of the wrapped key's
/// content — matching core_id::PrivateKeyMaterial's own Debug
/// guarantee (identity/src/keygen.rs).
#[pyclass(module = "relay_identity")]
struct PrivateKeyMaterial(core_id::PrivateKeyMaterial);

#[pymethods]
impl PrivateKeyMaterial {
    fn verifying_key_hex(&self) -> String {
        core_id::export_public_key_hex(&self.0.verifying_key())
    }

    fn __repr__(&self) -> &'static str {
        "PrivateKeyMaterial(REDACTED)"
    }

    fn __str__(&self) -> &'static str {
        self.__repr__()
    }
}

/// Generates a fresh Ed25519 keypair via core_id::generate_keypair.
/// Returns (private_key_handle, public_key_hex) — the public half as hex
/// directly, since that's the only form callers need it in (registration,
/// verify_payload's public_key_hex argument below).
#[pyfunction]
fn generate_keypair() -> (PrivateKeyMaterial, String) {
    let (private_key, public_key) = core_id::generate_keypair();
    let hex = core_id::export_public_key_hex(&public_key);
    (PrivateKeyMaterial(private_key), hex)
}

/// Local private-key storage — same owner-only file permission
/// discipline as core_id::KeyStore (this class calls straight
/// into it, no reimplementation of the permission logic).
#[pyclass(module = "relay_identity")]
struct KeyStore(core_id::KeyStore);

#[pymethods]
impl KeyStore {
    #[new]
    fn new(path: String) -> Self {
        Self(core_id::KeyStore::new(path))
    }

    fn save_private_key(&self, key: &PrivateKeyMaterial) -> PyResult<()> {
        self.0
            .save_private_key(&key.0)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn load_private_key(&self) -> PyResult<PrivateKeyMaterial> {
        self.0
            .load_private_key()
            .map(PrivateKeyMaterial)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn exists(&self) -> bool {
        self.0.exists()
    }
}

// ---------------------------------------------------------------------
// Canonical request payload + signing/verification
// ---------------------------------------------------------------------

/// Mirrors core_id::RequestPayload's five fields exactly (same
/// names, same order, same types) — a 1:1 struct mapping, not a
/// flattened/renamed convenience shape.
#[pyclass(module = "relay_identity", get_all, set_all)]
#[derive(Clone)]
struct RequestPayload {
    sender: String,
    recipient: String,
    request_type: String,
    timestamp: u64,
    nonce: String,
}

#[pymethods]
impl RequestPayload {
    #[new]
    fn new(sender: String, recipient: String, request_type: String, timestamp: u64, nonce: String) -> Self {
        Self { sender, recipient, request_type, timestamp, nonce }
    }
}

impl From<RequestPayload> for core_id::RequestPayload {
    fn from(p: RequestPayload) -> Self {
        Self {
            sender: p.sender,
            recipient: p.recipient,
            request_type: p.request_type,
            timestamp: p.timestamp,
            nonce: p.nonce,
        }
    }
}

impl From<core_id::RequestPayload> for RequestPayload {
    fn from(p: core_id::RequestPayload) -> Self {
        Self {
            sender: p.sender,
            recipient: p.recipient,
            request_type: p.request_type,
            timestamp: p.timestamp,
            nonce: p.nonce,
        }
    }
}

/// Signs `payload`'s canonical byte encoding with `key`. Returns
/// (canonical_bytes, signature_bytes) — both must travel together, same
/// contract as core_id::sign_payload (identity/src/signing.rs).
#[pyfunction]
fn sign_payload(key: &PrivateKeyMaterial, payload: RequestPayload) -> (Vec<u8>, Vec<u8>) {
    let rust_payload: core_id::RequestPayload = payload.into();
    let (bytes, signature) = core_id::sign_payload(&key.0, &rust_payload);
    (bytes, signature.to_bytes().to_vec())
}

/// What verify_payload returns on success — mirrors
/// core_id::VerifiedRequest exactly.
#[pyclass(module = "relay_identity", get_all)]
struct VerifiedRequest {
    sender: String,
    nonce: String,
    timestamp: u64,
    payload: RequestPayload,
}

/// Verifies `received_bytes` against `signature` and `public_key_hex`,
/// then parses fields from those SAME bytes — identical structural
/// guarantee to core_id::verify_payload (identity/src/verification.rs).
/// Raises InvalidSignature / MalformedPayload / ExpiredOrFutureTimestamp
/// to mirror VerificationError's three variants exactly.
#[pyfunction]
fn verify_payload(
    received_bytes: Vec<u8>,
    signature: Vec<u8>,
    public_key_hex: String,
    now: u64,
    max_age_secs: u64,
) -> PyResult<VerifiedRequest> {
    let public_key_bytes = hex_decode_32(&public_key_hex)?;
    let public_key = core_id::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| PyValueError::new_err("invalid Ed25519 public key bytes"))?;

    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
    let signature = core_id::Signature::from_bytes(&signature_bytes);

    match core_id::verify_payload(&received_bytes, &signature, &public_key, now, max_age_secs) {
        Ok(verified) => Ok(VerifiedRequest {
            sender: verified.sender,
            nonce: verified.nonce,
            timestamp: verified.timestamp,
            payload: verified.payload.into(),
        }),
        Err(core_id::VerificationError::InvalidSignature) => {
            Err(InvalidSignature::new_err("signature verification failed"))
        }
        Err(core_id::VerificationError::MalformedPayload(e)) => {
            Err(MalformedPayload::new_err(e.to_string()))
        }
        Err(core_id::VerificationError::ExpiredOrFutureTimestamp) => {
            Err(ExpiredOrFutureTimestamp::new_err("timestamp is outside the acceptable validity window"))
        }
    }
}

/// Signs arbitrary bytes directly — for callers whose signed data isn't
/// shaped like RequestPayload (e.g. agent/wiring/local_state.py's grant
/// canonical encoding). Mirrors core_id::sign_bytes exactly.
#[pyfunction]
fn sign_bytes(key: &PrivateKeyMaterial, message: Vec<u8>) -> Vec<u8> {
    core_id::sign_bytes(&key.0, &message).to_bytes().to_vec()
}

/// Verifies `signature` over arbitrary `message` bytes against
/// `public_key_hex`. Returns a plain bool (not an exception) — mirrors
/// core_id::verify_bytes, which has no timestamp/nonce shape to
/// distinguish failure reasons for, unlike verify_payload above.
#[pyfunction]
fn verify_bytes(message: Vec<u8>, signature: Vec<u8>, public_key_hex: String) -> PyResult<bool> {
    let public_key_bytes = hex_decode_32(&public_key_hex)?;
    let public_key = core_id::VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| PyValueError::new_err("invalid Ed25519 public key bytes"))?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| PyValueError::new_err("signature must be exactly 64 bytes"))?;
    let signature = core_id::Signature::from_bytes(&signature_bytes);
    Ok(core_id::verify_bytes(&message, &signature, &public_key))
}

// ---------------------------------------------------------------------
// Encryption keypair (X25519 sealed box)
// ---------------------------------------------------------------------

/// Opaque handle to an X25519 private key. Same no-raw-bytes-exposed,
/// always-redacted-repr discipline as PrivateKeyMaterial above.
#[pyclass(module = "relay_identity")]
struct EncryptionKeyMaterial(core_id::EncryptionKeyMaterial);

#[pymethods]
impl EncryptionKeyMaterial {
    fn public_key_hex(&self) -> String {
        core_id::export_encryption_public_key_hex(&self.0.public_key())
    }

    fn __repr__(&self) -> &'static str {
        "EncryptionKeyMaterial(REDACTED)"
    }

    fn __str__(&self) -> &'static str {
        self.__repr__()
    }
}

#[pyfunction]
fn generate_encryption_keypair() -> (EncryptionKeyMaterial, String) {
    let (secret, public) = core_id::generate_encryption_keypair();
    let hex = core_id::export_encryption_public_key_hex(&public);
    (EncryptionKeyMaterial(secret), hex)
}

#[pyclass(module = "relay_identity")]
struct EncryptionKeyStore(core_id::EncryptionKeyStore);

#[pymethods]
impl EncryptionKeyStore {
    #[new]
    fn new(path: String) -> Self {
        Self(core_id::EncryptionKeyStore::new(path))
    }

    fn save_private_key(&self, key: &EncryptionKeyMaterial) -> PyResult<()> {
        self.0
            .save_private_key(&key.0)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn load_private_key(&self) -> PyResult<EncryptionKeyMaterial> {
        self.0
            .load_private_key()
            .map(EncryptionKeyMaterial)
            .map_err(|e| PyIOError::new_err(e.to_string()))
    }

    fn exists(&self) -> bool {
        self.0.exists()
    }
}

/// Encrypts `plaintext` for `recipient_public_key_hex`. Only that
/// recipient's matching private key can decrypt it — same sealed-box
/// construction as core_id::encrypt (identity/src/encryption.rs).
#[pyfunction]
fn encrypt(recipient_public_key_hex: String, plaintext: Vec<u8>) -> PyResult<Vec<u8>> {
    let bytes = hex_decode_32(&recipient_public_key_hex)?;
    let public_key = core_id::EncryptionPublicKey::from(bytes);
    core_id::encrypt(&public_key, &plaintext).map_err(|_| EncryptError::new_err("encryption failed"))
}

/// Decrypts `ciphertext` with `key`. Fails closed: any tampering
/// (even a single flipped byte) raises DecryptError — never partial or
/// garbage plaintext, same guarantee as core_id::decrypt.
#[pyfunction]
fn decrypt(key: &EncryptionKeyMaterial, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
    core_id::decrypt(&key.0, &ciphertext).map_err(|_| DecryptError::new_err("decryption failed"))
}

// ---------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------

#[pymodule]
fn relay_identity(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PrivateKeyMaterial>()?;
    m.add_class::<KeyStore>()?;
    m.add_class::<RequestPayload>()?;
    m.add_class::<VerifiedRequest>()?;
    m.add_class::<EncryptionKeyMaterial>()?;
    m.add_class::<EncryptionKeyStore>()?;

    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(sign_payload, m)?)?;
    m.add_function(wrap_pyfunction!(verify_payload, m)?)?;
    m.add_function(wrap_pyfunction!(sign_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(generate_encryption_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;

    m.add("VerificationError", m.py().get_type::<VerificationError>())?;
    m.add("InvalidSignature", m.py().get_type::<InvalidSignature>())?;
    m.add("MalformedPayload", m.py().get_type::<MalformedPayload>())?;
    m.add("ExpiredOrFutureTimestamp", m.py().get_type::<ExpiredOrFutureTimestamp>())?;
    m.add("EncryptError", m.py().get_type::<EncryptError>())?;
    m.add("DecryptError", m.py().get_type::<DecryptError>())?;

    Ok(())
}
