# Trace-id generation for observability. NOT part of identity's signed
# payload format (RequestPayload's 5 fields are fixed by payload.rs) and
# NEVER gates any authorization decision — it travels as a plain
# X-Relay-Trace-Id HTTP header, purely for correlating log lines across
# a single logical operation (one ask/grant/revoke/MCP tool call).
# Same CSPRNG pattern as nonce.py; length is a log-correlation choice,
# not a security property, so it doesn't need to match identity's
# NONCE_HEX_LEN contract.

import secrets

TRACE_ID_HEX_LEN = 16


def generate_trace_id() -> str:
    return secrets.token_hex(TRACE_ID_HEX_LEN // 2)
