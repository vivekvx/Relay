//! Request signing — produces a signature over the canonical payload
//! bytes (payload.rs). The private key never leaves this function as
//! anything other than a signature.

use crate::keygen::PrivateKeyMaterial;
use crate::payload::RequestPayload;
use ed25519_dalek::{Signature, Signer};

/// Signs the canonical encoding of `payload`. Returns the exact bytes
/// that were signed alongside the signature — both must be transmitted
/// together, since verification checks the signature against these
/// specific bytes, not a re-derived encoding of the struct.
pub fn sign_payload(key: &PrivateKeyMaterial, payload: &RequestPayload) -> (Vec<u8>, Signature) {
    let canonical_bytes = payload.to_canonical_bytes();
    let signature = key.signing_key().sign(&canonical_bytes);
    (canonical_bytes, signature)
}

/// Signs arbitrary bytes directly — for callers whose signed data isn't
/// shaped like RequestPayload's fixed 5 fields (e.g. a grant record's
/// grantor/grantee/capsule_ids/expires_at). `sign_payload` stays the
/// right choice for anything that IS an ask/relay request; this exists
/// so callers with a different, equally-legitimate canonical encoding
/// don't have to force their data through RequestPayload's shape to get
/// a real signature instead of reimplementing Ed25519 themselves.
pub fn sign_bytes(key: &PrivateKeyMaterial, message: &[u8]) -> Signature {
    key.signing_key().sign(message)
}
