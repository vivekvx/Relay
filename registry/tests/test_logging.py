# Structured logging on the request-relay path (registry/logging_config.py,
# relay_service.py's logger.info calls) — asserts the right event name
# fires for received/relayed/rejected, and that trace_id round-trips into
# the log record. Mirrors test_registry.py's identity/signing helpers.

import logging
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from registry.services import identity_service, relay_service
from registry.tests.test_registry import encode_canonical_payload

NOW = datetime.now(timezone.utc)
VALID_NONCE = "abcdef0123456789abcdef0123456789"


def make_identity(session, handle: str):
    private_key = Ed25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes_raw().hex()
    x25519_public_key_hex = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    identity_service.register_identity(session, handle, public_key_hex, x25519_public_key_hex)
    return private_key


def sign_request(private_key, sender, recipient, request_type, timestamp, nonce):
    payload_bytes = encode_canonical_payload(sender, recipient, request_type, timestamp, nonce)
    signature_bytes = private_key.sign(payload_bytes)
    return payload_bytes.hex(), signature_bytes.hex()


def test_successful_relay_logs_received_and_relayed(session, caplog):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE)

    with caplog.at_level(logging.INFO, logger="registry.relay"):
        relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW, trace_id="test-trace-123")

    messages = [r.getMessage() for r in caplog.records]
    assert "relay_request_received" in messages
    assert "relay_request_relayed" in messages
    relayed_record = next(r for r in caplog.records if r.getMessage() == "relay_request_relayed")
    assert relayed_record.kv["trace_id"] == "test-trace-123"


def test_rejected_relay_logs_rejected_with_outcome(session, caplog):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE)
    bad_signature_hex = ("0" if signature_hex[0] != "0" else "1") + signature_hex[1:]

    with caplog.at_level(logging.INFO, logger="registry.relay"):
        try:
            relay_service.submit_relay_request(session, payload_hex, bad_signature_hex, NOW, trace_id="t2")
        except relay_service.RelayRejection:
            pass

    rejected = [r for r in caplog.records if r.getMessage() == "relay_request_rejected"]
    assert rejected
    assert rejected[0].kv["outcome"] == "invalid_signature"


def test_fetch_pending_logs_items_delivered(session, caplog):
    vivek_key = make_identity(session, "vivek")
    make_identity(session, "rohan")
    now_ts = int(time.time())
    payload_hex, signature_hex = sign_request(vivek_key, "vivek", "rohan", "ask", now_ts, VALID_NONCE)
    relay_service.submit_relay_request(session, payload_hex, signature_hex, NOW)

    with caplog.at_level(logging.INFO, logger="registry.relay"):
        relay_service.fetch_pending(session, "rohan", trace_id="t3")

    delivered = [r for r in caplog.records if r.getMessage() == "relay_items_delivered"]
    assert delivered
    assert delivered[0].kv["count"] == 1
