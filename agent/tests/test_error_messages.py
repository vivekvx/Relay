from wiring.error_messages import translate_error


def test_known_outcomes_get_a_concrete_fix():
    for outcome in (
        "invalid_signature",
        "unknown_recipient",
        "unknown_sender",
        "rate_limited",
        "expired_timestamp",
        "registry_unreachable",
        "replayed_nonce",
        "malformed_payload",
        "ciphertext_too_large",
        "not_found",
    ):
        fix = translate_error(outcome)
        assert fix and fix != outcome


def test_unknown_outcome_falls_back_to_message_or_labeled_unrecognized():
    assert translate_error("something_new", "raw detail") == "raw detail"
    assert translate_error("something_new") == "unrecognized error: something_new"
