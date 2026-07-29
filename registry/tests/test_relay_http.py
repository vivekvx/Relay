# Route-level HTTP test for GET /relay/pending/{recipient}.
#
# The rest of this suite (test_registry.py) only ever calls
# relay_service.fetch_pending() directly — never through the actual
# FastAPI route. That let a real bug hide: fetch_pending's "payload"
# field was raw LargeBinary bytes, not valid UTF-8 in general (it's
# identity/'s canonical byte encoding — length-prefixed fields, an
# 8-byte big-endian timestamp), and jsonable_encoder cannot serialize
# arbitrary bytes. The route would 500 on any real payload whose bytes
# weren't coincidentally valid UTF-8. This test goes through the actual
# HTTP layer (TestClient) with a real signed request, so this class of
# bug can't hide behind service-layer-only test coverage again.

import struct
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from registry.app import app
from registry.db import get_session
from registry.services import identity_service

VALID_NONCE = "0123456789abcdef0123456789abcdef"


def encode_canonical_payload(sender, recipient, request_type, timestamp, nonce) -> bytes:
    def field(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack(">I", len(b)) + b

    out = b""
    out += field(sender)
    out += field(recipient)
    out += field(request_type)
    out += struct.pack(">Q", timestamp)
    out += field(nonce)
    return out


def make_identity(session, handle: str):
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    x25519_public_key_hex = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    identity_service.register_identity(session, handle, public_key_hex, x25519_public_key_hex)
    return private_key


def test_get_pending_over_http_serializes_a_real_non_utf8_payload(session):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    session.commit()
    now_ts = int(time.time())

    # A realistic canonical payload: the 4-byte big-endian length
    # prefixes and 8-byte big-endian timestamp bytes here are exactly
    # the kind of byte sequence that is NOT valid UTF-8 in general —
    # this is what makes the test meaningful, not a contrived case.
    payload_bytes = encode_canonical_payload("vivek", "rohan", "ask", now_ts, VALID_NONCE)
    signature_bytes = vivek_key.sign(payload_bytes)

    app.dependency_overrides[get_session] = lambda: session
    try:
        client = TestClient(app)
        submit_response = client.post(
            "/relay",
            json={
                "payload_hex": payload_bytes.hex(),
                "signature_hex": signature_bytes.hex(),
            },
        )
        assert submit_response.status_code == 202, submit_response.text

        poll_response = client.get("/relay/pending/rohan")
        assert poll_response.status_code == 200, poll_response.text

        body = poll_response.json()
        assert len(body) == 1
        item = body[0]
        assert item["sender"] == "vivek"
        assert item["recipient"] == "rohan"
        assert item["nonce"] == VALID_NONCE
        assert bytes.fromhex(item["payload_hex"]) == payload_bytes
        assert bytes.fromhex(item["signature_hex"]) == signature_bytes
        assert item["content_ciphertext_hex"] is None
    finally:
        app.dependency_overrides.clear()
