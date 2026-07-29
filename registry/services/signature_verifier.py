# Ed25519 signature verification using the `cryptography` library (a
# vetted, widely-used implementation) — this does NOT hand-roll the
# elliptic-curve math itself, per the task's explicit instruction not
# to reimplement Ed25519. See registry/ARCHITECTURE.md judgment call #1
# for why this is an independent verifier against identity's canonical
# byte format rather than a direct call into the Rust module (no FFI
# bridge was built; that would be a separate, larger task).

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_signature(public_key_hex: str, payload_bytes: bytes, signature_bytes: bytes) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(signature_bytes, payload_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False
