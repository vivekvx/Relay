//! Relay identity/signing module. See ARCHITECTURE.md in this crate
//! for the full design rationale.
//!
//! Own standalone Rust module, within the Relay repo. Models vaultd's
//! architectural pattern (local daemon, local key storage, no network
//! exposure of raw keys) but does not import, submodule, fork, or
//! otherwise depend on the vaultd repo (CLAUDE.md §2, §4).

pub mod encryption;
pub mod keygen;
pub mod payload;
pub mod signing;
pub mod storage;
pub mod verification;

pub use encryption::{
    decrypt, encrypt, export_encryption_public_key_hex, generate_encryption_keypair,
    DecryptError, EncryptError, EncryptionKeyMaterial, EncryptionKeyStore,
};
pub use keygen::{export_public_key_hex, generate_keypair, PrivateKeyMaterial};
pub use payload::{PayloadError, RequestPayload, NONCE_HEX_LEN};
pub use signing::sign_payload;
pub use storage::KeyStore;
pub use verification::{
    verify_payload, VerificationError, VerifiedRequest, DEFAULT_MAX_REQUEST_AGE_SECS,
};

pub use crypto_box::{PublicKey as EncryptionPublicKey, SecretKey as EncryptionSecretKey};
pub use ed25519_dalek::{Signature, VerifyingKey};

#[cfg(test)]
mod tests;
