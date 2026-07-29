# Canonical payload decode — MUST match identity/src/payload.rs's
# encoding exactly, since the registry verifies signatures produced by
# that module. Field order: sender, recipient, request_type, timestamp,
# nonce. Each string field: u32 big-endian length prefix + UTF-8 bytes.
# timestamp: u64 big-endian, unix seconds. Trailing bytes rejected.
#
# This module does NOT implement Ed25519 verification itself (see
# signature_verifier.py, which uses the `cryptography` library) — this
# is only the byte-format decoder, reimplemented in Python because the
# identity module is a separate Rust crate with no FFI bridge built
# (see registry/ARCHITECTURE.md judgment call #1).

import re
import struct
from dataclasses import dataclass

NONCE_HEX_LEN = 32
_NONCE_RE = re.compile(rf"^[0-9a-f]{{{NONCE_HEX_LEN}}}$")


class PayloadDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class DecodedPayload:
    sender: str
    recipient: str
    request_type: str
    timestamp: int
    nonce: str


def _read_field(buf: bytes, offset: int) -> tuple[str, int]:
    if offset + 4 > len(buf):
        raise PayloadDecodeError("payload ended before all fields were read")
    (length,) = struct.unpack_from(">I", buf, offset)
    offset += 4
    if offset + length > len(buf):
        raise PayloadDecodeError("payload ended before all fields were read")
    field_bytes = buf[offset : offset + length]
    try:
        value = field_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadDecodeError("a string field was not valid UTF-8") from exc
    return value, offset + length


def decode_canonical_payload(buf: bytes) -> DecodedPayload:
    offset = 0
    sender, offset = _read_field(buf, offset)
    recipient, offset = _read_field(buf, offset)
    request_type, offset = _read_field(buf, offset)
    if offset + 8 > len(buf):
        raise PayloadDecodeError("payload ended before all fields were read")
    (timestamp,) = struct.unpack_from(">Q", buf, offset)
    offset += 8
    nonce, offset = _read_field(buf, offset)
    if offset != len(buf):
        raise PayloadDecodeError("payload has bytes after the nonce field")
    if not _NONCE_RE.match(nonce):
        raise PayloadDecodeError(f"nonce is missing or not {NONCE_HEX_LEN} hex characters")
    return DecodedPayload(
        sender=sender,
        recipient=recipient,
        request_type=request_type,
        timestamp=timestamp,
        nonce=nonce,
    )
