//! Request verification. PRD.md §5 R2 (identity spoofing), R6
//! (replay/relay abuse).
//!
//! Rejects: invalid signatures; signatures valid for different bytes
//! than claimed (see the comment on `verify_payload` below — this is
//! the exact risk point 4 of the task called out); expired/future
//! timestamps outside the configured window; missing or malformed
//! nonces. Nonce *uniqueness* (replay-within-window) is NOT tracked
//! here — this module has no persistence. It returns the
//! (sender, nonce, timestamp) tuple so the caller (registry or local
//! agent) can check that against its own seen-nonce store.

use crate::payload::{PayloadError, RequestPayload};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fmt;

/// Default acceptable age for a request, in seconds, before it's
/// rejected as expired. Also used symmetrically for future-dated
/// requests (clock skew tolerance) — see `verify_payload`.
pub const DEFAULT_MAX_REQUEST_AGE_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidSignature,
    MalformedPayload(PayloadError),
    ExpiredOrFutureTimestamp,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::InvalidSignature => write!(f, "signature verification failed"),
            VerificationError::MalformedPayload(e) => write!(f, "malformed payload: {}", e),
            VerificationError::ExpiredOrFutureTimestamp => {
                write!(f, "timestamp is outside the acceptable validity window")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// What the caller gets back on success: the exact fields needed to
/// dedupe replays and to route the request onward. Deliberately does
/// NOT persist or track nonces itself — that's the caller's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequest {
    pub sender: String,
    pub nonce: String,
    pub timestamp: u64,
    pub payload: RequestPayload,
}

/// Verifies `received_bytes` (the exact bytes that arrived over the
/// wire) against `signature` and `public_key`, then parses fields from
/// those SAME bytes.
///
/// Risk this structurally avoids: verifying a signature against one
/// buffer and then reading claimed fields from a different,
/// independently-reconstructed buffer (e.g. "verify raw bytes, but
/// then re-serialize a parsed struct and trust that instead"). If the
/// re-serialization doesn't roundtrip byte-for-byte, an attacker could
/// get a signature validated against bytes A while the caller acts on
/// fields decoded from bytes B. This function only ever parses
/// `received_bytes` itself — never a reconstruction of it.
pub fn verify_payload(
    received_bytes: &[u8],
    signature: &Signature,
    public_key: &VerifyingKey,
    now: u64,
    max_age_secs: u64,
) -> Result<VerifiedRequest, VerificationError> {
    public_key
        .verify(received_bytes, signature)
        .map_err(|_| VerificationError::InvalidSignature)?;

    // Parsed from `received_bytes` itself, not a separately built copy.
    let payload = RequestPayload::from_canonical_bytes(received_bytes)
        .map_err(VerificationError::MalformedPayload)?;

    let age_ok = now.checked_sub(payload.timestamp).unwrap_or(0) <= max_age_secs;
    let future_ok = payload.timestamp.checked_sub(now).unwrap_or(0) <= max_age_secs;
    if !age_ok || !future_ok {
        return Err(VerificationError::ExpiredOrFutureTimestamp);
    }

    Ok(VerifiedRequest {
        sender: payload.sender.clone(),
        nonce: payload.nonce.clone(),
        timestamp: payload.timestamp,
        payload,
    })
}

/// Verifies `signature` over arbitrary `message` bytes against
/// `public_key` — the generic counterpart to `sign_bytes` (signing.rs).
/// No timestamp/nonce/replay handling here (there's no assumed field
/// shape to check them in); a caller with freshness/replay
/// requirements for its own byte format checks those itself, same as
/// verify_payload's caller already does for nonce persistence.
pub fn verify_bytes(message: &[u8], signature: &Signature, public_key: &VerifyingKey) -> bool {
    public_key.verify(message, signature).is_ok()
}
