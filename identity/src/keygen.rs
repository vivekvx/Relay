//! Ed25519 keypair generation, and a private-key wrapper that
//! structurally cannot leak key material through Debug/Display.
//!
//! PRD.md §7 Tech Stack: identity/signing is Relay's own standalone
//! Rust module. Models vaultd's pattern (local daemon, local key
//! storage, no network exposure of raw keys) without depending on
//! vaultd's codebase in any way.

use crypto_common::Generate;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fmt;

/// Wraps the private signing key so it can never be printed, logged, or
/// included in an error message by accident. `Debug` always emits a
/// fixed, content-independent string — by construction, not by
/// discipline. There is deliberately no `Display` impl at all.
///
/// The underlying `ed25519_dalek::SigningKey` also zeroizes its bytes
/// on drop (the "zeroize" feature is enabled in Cargo.toml), so key
/// material doesn't linger in freed memory either.
pub struct PrivateKeyMaterial(pub(crate) SigningKey);

impl fmt::Debug for PrivateKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally ignores `self` entirely — there is no code path
        // in this impl that can ever touch the key bytes.
        write!(f, "PrivateKeyMaterial(REDACTED)")
    }
}

impl PrivateKeyMaterial {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

/// Generates a fresh Ed25519 keypair using the OS CSPRNG (via rand
/// 0.10's `TryCryptoRng`-based RNG — the OS-backed generator in this
/// crate version is fallible-by-design, hence `try_generate_from_rng`
/// + `expect`; failure here means the OS entropy source itself failed,
/// which is not a case this module can recover from). Never persists
/// anything — call `storage::KeyStore::save_private_key` to store it.
pub fn generate_keypair() -> (PrivateKeyMaterial, VerifyingKey) {
    let mut rng = rand::rng();
    let signing_key = SigningKey::try_generate_from_rng(&mut rng)
        .expect("OS CSPRNG failed to provide entropy for key generation");
    let verifying_key = signing_key.verifying_key();
    (PrivateKeyMaterial(signing_key), verifying_key)
}

/// Public key export, hex-encoded — the format suitable for
/// registration with the hosted registry (registry stores public keys
/// and routing metadata only; sending it over the network is a
/// separate, out-of-scope concern for this module).
pub fn export_public_key_hex(key: &VerifyingKey) -> String {
    hex_encode(key.as_bytes())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
