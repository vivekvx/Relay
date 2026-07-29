//! Canonical request payload encoding — what actually gets signed.
//!
//! Ambiguous serialization is a real vulnerability class: naive field
//! concatenation (e.g. `sender + recipient`) lets an attacker shift
//! bytes between fields ("ab"+"c" vs "a"+"bc") and produce a different
//! logical payload with the same signed bytes. This module avoids that
//! by length-prefixing every variable-length field, so the byte
//! encoding of a given (sender, recipient, request_type, timestamp,
//! nonce) tuple is unique and unambiguous to decode.
//!
//! Field order (fixed, part of the canonical format):
//! sender, recipient, request_type, timestamp, nonce.
//! Each string field: u32 big-endian length prefix + UTF-8 bytes.
//! timestamp: u64 big-endian, unix seconds.
//! Trailing bytes after the nonce are rejected (no extension room).

use std::fmt;

/// Nonces must be exactly this many hex characters (16 random bytes,
/// hex-encoded) — fixed format, not just "non-empty".
pub const NONCE_HEX_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPayload {
    pub sender: String,
    pub recipient: String,
    pub request_type: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadError {
    UnexpectedEnd,
    InvalidUtf8,
    TrailingData,
    MalformedNonce,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::UnexpectedEnd => write!(f, "payload ended before all fields were read"),
            PayloadError::InvalidUtf8 => write!(f, "a string field was not valid UTF-8"),
            PayloadError::TrailingData => write!(f, "payload has bytes after the nonce field"),
            PayloadError::MalformedNonce => {
                write!(f, "nonce is missing or not {} hex characters", NONCE_HEX_LEN)
            }
        }
    }
}

impl std::error::Error for PayloadError {}

impl RequestPayload {
    pub fn is_nonce_well_formed(&self) -> bool {
        self.nonce.len() == NONCE_HEX_LEN && self.nonce.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Canonical byte encoding — this is the exact wire format that gets
    /// signed and transmitted.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, &self.sender);
        write_field(&mut out, &self.recipient);
        write_field(&mut out, &self.request_type);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        write_field(&mut out, &self.nonce);
        out
    }

    /// Parses the canonical format back into fields — from the EXACT
    /// bytes handed in, never from an independently reconstructed
    /// buffer. Callers verifying a signature must parse fields from the
    /// same bytes they verified (see verification.rs) — parsing a
    /// separately-reserialized copy would let a signature validated
    /// over bytes A be attributed to fields decoded from different
    /// bytes B, defeating the whole point of the signature.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, PayloadError> {
        let mut cursor = bytes;
        let sender = read_field(&mut cursor)?;
        let recipient = read_field(&mut cursor)?;
        let request_type = read_field(&mut cursor)?;
        let timestamp = read_u64(&mut cursor)?;
        let nonce = read_field(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(PayloadError::TrailingData);
        }
        let payload = RequestPayload {
            sender,
            recipient,
            request_type,
            timestamp,
            nonce,
        };
        if !payload.is_nonce_well_formed() {
            return Err(PayloadError::MalformedNonce);
        }
        Ok(payload)
    }
}

fn write_field(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_field(cursor: &mut &[u8]) -> Result<String, PayloadError> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return Err(PayloadError::UnexpectedEnd);
    }
    let (field_bytes, rest) = cursor.split_at(len);
    *cursor = rest;
    String::from_utf8(field_bytes.to_vec()).map_err(|_| PayloadError::InvalidUtf8)
}

fn read_u32(cursor: &mut &[u8]) -> Result<u32, PayloadError> {
    if cursor.len() < 4 {
        return Err(PayloadError::UnexpectedEnd);
    }
    let (len_bytes, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_be_bytes(len_bytes.try_into().unwrap()))
}

fn read_u64(cursor: &mut &[u8]) -> Result<u64, PayloadError> {
    if cursor.len() < 8 {
        return Err(PayloadError::UnexpectedEnd);
    }
    let (ts_bytes, rest) = cursor.split_at(8);
    *cursor = rest;
    Ok(u64::from_be_bytes(ts_bytes.try_into().unwrap()))
}
