//! Local private-key storage with restrictive file permissions.
//!
//! Threat this defends against: another *unprivileged* local account
//! (or process running as a different user) reading the private key
//! file off disk.
//!
//! Threat this does NOT defend against: a compromised or malicious
//! process running as the SAME user account (it can read any file that
//! user can read, permissions or not), a compromised OS/kernel, physical
//! disk access without full-disk encryption, or a user who copies the
//! key file elsewhere themselves. File permissions are a local-privilege
//! boundary, not a confidentiality guarantee against the account owner.

use crate::keygen::PrivateKeyMaterial;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct KeyStore {
    path: PathBuf,
}

impl KeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn save_private_key(&self, key: &PrivateKeyMaterial) -> io::Result<()> {
        let file = create_owner_only_file(&self.path)?;
        use std::io::Write;
        let mut file = file;
        file.write_all(&key.to_bytes())?;
        file.sync_all()?;
        // Re-assert permissions after write in case the file already
        // existed with looser permissions before this call.
        restrict_permissions(&self.path)?;
        Ok(())
    }

    pub fn load_private_key(&self) -> io::Result<PrivateKeyMaterial> {
        let bytes = fs::read(&self.path)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "key file is not 32 bytes")
        })?;
        Ok(PrivateKeyMaterial::from_bytes(&arr))
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

// pub(crate): reused by encryption.rs's own key store (same file-
// permission discipline for the X25519 private key) — visibility only,
// no behavior change to the signing key storage path above.
//
// Non-Unix platforms (Windows) have no equivalent owner-only file
// permission implemented here. Rather than silently writing an
// unprotected private key file (the previous behavior — a disclosed
// but silent gap), this refuses outright: a security-critical module
// should fail loud, not degrade quietly to an unprotected file a
// caller could easily miss. Real Windows support (ACL restriction via
// the Windows security APIs) is a real follow-up, not implemented —
// see ARCHITECTURE.md.
//
// The `is_unix` parameter exists so the refusal branch is unit-testable
// on any host, including Unix CI, without actually needing to run on a
// non-Unix machine: production code always calls the public wrappers
// below, which pass `cfg!(unix)` — the real, compile-time-accurate
// platform check. Tests call `*_for_platform` directly with
// `is_unix: false` to exercise the refusal path deterministically. See
// tests.rs's `refuses_to_write_key_file_when_platform_is_not_unix`.

pub(crate) fn create_owner_only_file_for_platform(path: &Path, is_unix: bool) -> io::Result<fs::File> {
    if !is_unix {
        return Err(non_unix_unsupported_error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // owner read/write only, set at creation time
            .open(path)
    }
    #[cfg(not(unix))]
    {
        unreachable!("is_unix=true was passed on a non-Unix build — production code never does this")
    }
}

pub(crate) fn restrict_permissions_for_platform(path: &Path, is_unix: bool) -> io::Result<()> {
    if !is_unix {
        return Err(non_unix_unsupported_error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        unreachable!("is_unix=true was passed on a non-Unix build — production code never does this")
    }
}

fn non_unix_unsupported_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "secure local private-key storage (owner-only file permissions) is not yet implemented \
         on this platform — refusing to write an unprotected private key file to disk. \
         Windows/non-Unix support is a real follow-up, not implemented.",
    )
}

pub(crate) fn create_owner_only_file(path: &Path) -> io::Result<fs::File> {
    create_owner_only_file_for_platform(path, cfg!(unix))
}

pub(crate) fn restrict_permissions(path: &Path) -> io::Result<()> {
    restrict_permissions_for_platform(path, cfg!(unix))
}
