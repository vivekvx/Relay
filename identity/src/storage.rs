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
#[cfg(unix)]
pub(crate) fn create_owner_only_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // owner read/write only, set at creation time
        .open(path)
}

#[cfg(unix)]
pub(crate) fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub(crate) fn create_owner_only_file(path: &Path) -> io::Result<fs::File> {
    // TODO (disclosed gap, not silently skipped): no Windows ACL
    // restriction is applied here. A correct equivalent would set an
    // ACL granting access only to the current user (e.g. via the
    // Windows security APIs), which is out of scope for this task —
    // see ARCHITECTURE.md and the judgment-call note in the task
    // summary. This path currently offers no local-privilege
    // protection on non-Unix systems.
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}
