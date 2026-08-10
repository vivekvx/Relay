# Human-readable error translation, shared by both the CLI and the MCP
# server so the same outcome always gets the same fix instruction rather
# than each surface inventing its own wording (or letting a raw
# exception/outcome string reach the caller unexplained).

_FIXES = {
    "invalid_signature": (
        "Your local key doesn't match what's registered. Run `relay whoami` to check, "
        "then `relay register` or `relay init --force` to fix."
    ),
    "unknown_recipient": "That handle isn't registered on this registry yet. Ask them to run `relay register`.",
    "unknown_sender": "Your handle isn't registered. Run `relay register` first.",
    "rate_limited": "Too many requests to this recipient — wait and try again.",
    "expired_timestamp": "This request's clock/timestamp window expired — check your system clock, then retry.",
    "registry_unreachable": "Can't reach the registry. Check your network, or run `relay doctor` for a full diagnosis.",
    "replayed_nonce": "This exact request was already sent — if you meant to resend, try again (a fresh nonce is generated automatically).",
    "malformed_payload": "The request payload was malformed — this points at a bug, not a config issue; re-run and report if it persists.",
    "ciphertext_too_large": "The encrypted content exceeds the registry's size limit — shorten the question/content.",
    "not_found": "That id doesn't match anything on record.",
}


def translate_error(outcome: str, message: str = "") -> str:
    return _FIXES.get(outcome, message or f"unrecognized error: {outcome}")
