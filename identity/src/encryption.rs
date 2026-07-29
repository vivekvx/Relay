//! X25519 encryption, separate from the Ed25519 signing keypair in
//! keygen.rs. Two keypairs, two purposes:
//!
//! - Ed25519 (keygen.rs, signing.rs, verification.rs): proves identity
//!   — "this request really came from this sender."
//! - X25519 (this module): encrypts content for a specific recipient —
//!   "only this recipient can read this."
//!
//! These are deliberately NOT the same key reused for two purposes.
//! Using a single Ed25519 key for both signing and Diffie-Hellman key
//! exchange is a known cryptographic footgun (the two operations can
//! interact in ways that leak information about the key or enable
//! cross-protocol attacks) — ed25519-dalek's own docs warn against it
//! explicitly. Keeping them as separate keypairs, generated and stored
//! independently, avoids that class of risk entirely rather than
//! relying on careful usage to avoid it.
//!
//! Construction: `crypto_box`'s "sealed box" (`PublicKey::seal` /
//! `SecretKey::unseal`), a Rust implementation of libsodium's
//! `crypto_box_seal` — X25519 ECDH + XSalsa20-Poly1305 AEAD, an
//! established, audited construction (this module calls it, it does
//! not implement ECDH or the AEAD cipher itself). Sealed box specifically
//! (not the authenticated `SalsaBox` variant) because the encrypt
//! function's contract only takes the recipient's public key — no
//! sender private key is required or used; the outer request envelope
//! is already Ed25519-signed, so sender authenticity is established at
//! that layer, not by the encryption itself. `crypto_box::seal`
//! generates a fresh ephemeral keypair per call internally and
//! prepends the ephemeral public key to the ciphertext, so the
//! recipient can always decrypt without any prior key exchange.

use crypto_box::aead::OsRng;
use crypto_box::{PublicKey, SecretKey};
use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::storage::{create_owner_only_file, restrict_permissions};

/// Wraps the X25519 private key the same way `PrivateKeyMaterial`
/// wraps the Ed25519 one: `Debug` always emits a fixed,
/// content-independent string, never the key bytes. `crypto_box::SecretKey`
/// itself already redacts Debug and zeroizes on drop (see its own impl);
/// this wrapper exists so identity/'s two private key types have the
/// same guarantee via the same pattern, not by relying on the upstream
/// crate's choice alone.
pub struct EncryptionKeyMaterial(SecretKey);

impl fmt::Debug for EncryptionKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionKeyMaterial(REDACTED)")
    }
}

impl EncryptionKeyMaterial {
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretKey::from_bytes(bytes))
    }
}

/// Generates a fresh X25519 keypair using the OS CSPRNG.
pub fn generate_encryption_keypair() -> (EncryptionKeyMaterial, PublicKey) {
    let secret_key = SecretKey::generate(&mut OsRng);
    let public_key = secret_key.public_key();
    (EncryptionKeyMaterial(secret_key), public_key)
}

/// Hex-encoded public key export, in the format suitable for
/// registration with the hosted registry alongside the Ed25519 public
/// key (see keygen.rs's `export_public_key_hex` for the signing key).
pub fn export_encryption_public_key_hex(key: &PublicKey) -> String {
    crate::keygen::hex_encode(key.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptError;

/// Encrypts `plaintext` for `recipient_public_key`. Only that
/// recipient's matching private key can decrypt it.
pub fn encrypt(recipient_public_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, EncryptError> {
    recipient_public_key
        .seal(&mut OsRng, plaintext)
        .map_err(|_| EncryptError)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptError;

/// Decrypts `ciphertext` using this identity's X25519 private key.
/// Fails closed: any tampering (even a single flipped byte) makes the
/// AEAD tag check fail, and this returns `Err` — never partial or
/// garbage plaintext.
pub fn decrypt(key: &EncryptionKeyMaterial, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    key.0.unseal(ciphertext).map_err(|_| DecryptError)
}

/// Local storage for the X25519 private key — same owner-only file
/// permission discipline as `storage::KeyStore` (reuses its helpers
/// directly rather than duplicating the permission logic).
pub struct EncryptionKeyStore {
    path: PathBuf,
}

impl EncryptionKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn save_private_key(&self, key: &EncryptionKeyMaterial) -> io::Result<()> {
        let mut file = create_owner_only_file(&self.path)?;
        use std::io::Write;
        file.write_all(&key.to_bytes())?;
        file.sync_all()?;
        restrict_permissions(&self.path)?;
        Ok(())
    }

    pub fn load_private_key(&self) -> io::Result<EncryptionKeyMaterial> {
        let bytes = fs::read(&self.path)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "key file is not 32 bytes")
        })?;
        Ok(EncryptionKeyMaterial::from_bytes(arr))
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}
